"""One owned Arkade stack and one concrete offline-recovery scenario."""
from __future__ import annotations
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.request
import urllib.parse

from paths import BACKUP, FULMINE, HARNESS

BINARIES = ("fulmine", "recovery-client", "recovery-tests", "backup-server")
NGINX_IMAGE = "nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236"
OFFLINE_RENEWAL_CHECKS = frozenset((
    "wallet_state_absent", "seed_file_absent", "config_seed_absent",
    "original_intent_signature_valid", "retargeted_intent_signature_rejected",
    "original_forfeit_signature_valid", "retargeted_forfeit_signature_rejected",
    "retargeted_scope_differs", "rewritten_grant_signature_rejected",
    "replacement_has_no_delegate_key", "original_request_rejected",
    "retargeted_request_rejected", "original_input_spent", "replacement_unspent",
))
OFFLINE_RENEWAL_REJECTIONS = frozenset(("original_request", "retargeted_request", "intent", "grant"))


def binary_manifest(directory, supplied=None):
    hashes = {}
    for name in BINARIES:
        digest = hashlib.sha256()
        with (directory/name).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b""):
                digest.update(chunk)
        hashes[name] = digest.hexdigest()
    sources = None
    if supplied is not None:
        if not isinstance(supplied, dict) or not isinstance(supplied.get("sha256"), dict):
            raise RuntimeError("invalid build manifest")
        if any(supplied["sha256"].get(name) != digest for name, digest in hashes.items()):
            raise RuntimeError("prebuilt binary differs from build manifest")
        sources = supplied.get("sources")
        if not isinstance(sources, dict) or set(sources) != {"fulmine", "backup"} or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value) for value in sources.values()):
            raise RuntimeError("build manifest needs full Fulmine and backup Git revisions")
    return {"sources": sources, "sha256": hashes}


def request(url, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.status == 204:
            return True
        return json.load(response)


def wait_for(label, function, timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = function()
            if result:
                return result
        except (OSError, ValueError) as exc:
            last = type(exc).__name__
        time.sleep(0.5)
    raise RuntimeError(f"{label} did not become ready ({last})")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Stack:
    def __init__(self, run):
        self.run = run
        self.project = "recovery-" + run.id
        self.config = json.loads((HARNESS / "live.compose.json").read_text())
        self.config["networks"]["default"]["internal"] = False
        for name, ports in {"bitcoin": [18443], "mempool_api": [8999], "arkd": [7070, 7071], "arkd-wallet": [6060]}.items():
            self.config["services"][name]["ports"] = [f"127.0.0.1::{port}" for port in ports]
        for service in self.config["services"].values():
            service["labels"] = {"bull.recovery.run": run.id}
        for volume in self.config["volumes"].values():
            volume["labels"] = {"bull.recovery.run": run.id}
        self.config["networks"]["default"]["labels"] = {"bull.recovery.run": run.id}
        self.path = run.directory / "live-compose.json"
        self.path.write_text(json.dumps(self.config))
        self.argv = ["docker", "compose", "--project-name", self.project, "-f", str(self.path)]
        self.counter = 0
        self.processes = []

    def compose(self, *args, timeout=180):
        self.counter += 1
        return self.run.command(f"live-compose-{self.counter}", self.argv + list(args), timeout=timeout)

    def endpoint(self, service, port):
        address = self.compose("port", service, str(port)).strip()
        if not address.startswith("127.0.0.1:"):
            raise RuntimeError("live service escaped loopback binding")
        return "http://" + address

    def rpc(self, method, params=(), wallet=""):
        req = urllib.request.Request(self.bitcoin + wallet,
            json.dumps({"jsonrpc":"1.0", "id":"live", "method":method, "params":params}).encode())
        req.add_header("Authorization", "Basic " + base64.b64encode(b"admin1:123").decode())
        with urllib.request.urlopen(req, timeout=20) as response:
            result = json.load(response)
        if result.get("error"):
            raise RuntimeError("Bitcoin RPC failed: " + method)
        return result["result"]

    def mine(self, blocks=1):
        return self.rpc("generatetoaddress", [blocks, self.mining_address])

    def process(self, name, argv, env=None):
        log = open(self.run.directory / (name + ".log"), "wb", opener=lambda p,f: os.open(p,f,0o600))
        process = subprocess.Popen(argv, env=env or self.run.env, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append((process,log))
        return process

    def backup_proxy(self, port, upstream_port):
        # The deployed Rust router trusts only the reverse proxy's overwritten
        # source header. Exercise that boundary without teaching clients to set it.
        config = self.run.directory / "backup-nginx.conf"
        config.write_text("events {}\nhttp { access_log off; server {\n"
            f"listen 127.0.0.1:{port};\n"
            "client_max_body_size 2m;\nlocation / {\n"
            f"proxy_pass http://127.0.0.1:{upstream_port};\n"
            "proxy_set_header X-Real-IP $remote_addr;\n"
            "proxy_set_header Host $http_host;\n} } }\n")
        self.config["services"]["backup-proxy"] = {
            "image": NGINX_IMAGE, "network_mode": "host", "mem_limit": "32m",
            "pids_limit": 64, "labels": {"bull.recovery.run": self.run.id},
            "volumes": [{"type": "bind", "source": str(config),
                         "target": "/etc/nginx/nginx.conf", "read_only": True}],
            "logging": {"driver": "json-file", "options": {"max-size": "1m", "max-file": "1"}},
        }
        self.path.write_text(json.dumps(self.config))
        self.compose("up", "-d", "--pull", "never", "backup-proxy")

    def close(self):
        failures = []
        for process, log in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            log.close()
        # Capture only this project's logs, then check ownership before deletion.
        try:
            self.compose("logs", "--no-color", "--tail", "150", timeout=30)
        except Exception as exc:
            failures.append("log collection: " + type(exc).__name__)
        ids = self.compose("ps", "--all", "--quiet").split()
        for ident in ids:
            label = self.run.command("live-owner-"+ident[:12], ["docker","inspect","--format",'{{index .Config.Labels "bull.recovery.run"}}',ident]).strip()
            if label != self.run.id:
                raise RuntimeError("refusing to clean an unowned live container")
        self.compose("down", "--volumes", "--timeout", "5", timeout=60)
        if failures:
            raise RuntimeError("live cleanup: " + "; ".join(failures))


def completed_refresh(data, logfile):
    databases = list(data.rglob("fulmine.db"))
    if len(databases) != 1:
        return None
    with sqlite3.connect(f"file:{databases[0]}?mode=ro", uri=True) as db:
        rows = db.execute("SELECT id, status, commitment_txid FROM delegate_task").fetchall()
    if not rows or any(row[1] == 0 for row in rows):
        return None
    if len(rows) != 1 or rows[0][1] != 1:
        raise RuntimeError("protected delegate task did not complete successfully")
    task, _, commitment = rows[0]
    lines = logfile.read_text().splitlines()
    ack = [i for i, line in enumerate(lines) if "recovery backup acknowledged" in line and f"commitment={commitment}" in line and f"task={task}" in line]
    submit = [i for i, line in enumerate(lines) if "recovery forfeits submission starting" in line and f"commitment={commitment}" in line]
    if len(ack) != 1 or len(submit) != 1 or ack[0] >= submit[0]:
        raise RuntimeError("missing candidate-bound acknowledgement before forfeit submission")
    ciphertext = re.search(r"ciphertext=([0-9a-f]{64})", lines[ack[0]])
    if not ciphertext:
        raise RuntimeError("acknowledgement lacks ciphertext hash")
    return {"task_id": task, "commitment_txid": commitment, "ciphertext_sha256": ciphertext[1], "backup_ack_sequence": ack[0]+1, "forfeit_submit_sequence": submit[0]+1}


def failed_refresh(data, logfile):
    databases = list(data.rglob("fulmine.db"))
    if len(databases) != 1:
        return None
    with sqlite3.connect(f"file:{databases[0]}?mode=ro", uri=True) as db:
        rows = db.execute("SELECT status, commitment_txid FROM delegate_task").fetchall()
    if not rows or any(row[0] == 0 for row in rows):
        return None
    if len(rows) != 1 or rows[0][0] != 2 or rows[0][1]:
        raise RuntimeError("backup outage did not fail the protected task")
    if not list((data/"recovery-prototype").glob("outbox-*.json")):
        raise RuntimeError("backup outage never reached candidate publication")
    log = logfile.read_text()
    if "recovery forfeits submission starting" in log or "recovery backup acknowledged" in log:
        raise RuntimeError("backup outage crossed the protected publication gate")
    return True


def offline_renewal_evidence(path, requested, refresh):
    evidence = json.loads(path.read_text())
    if (evidence.get("status") != "blocked" or
            type(evidence.get("requested_refresh_count")) is not int or evidence["requested_refresh_count"] != requested or
            type(evidence.get("completed_refresh_count")) is not int or evidence["completed_refresh_count"] != 1 or
            type(evidence.get("blocked_round")) is not int or evidence["blocked_round"] != 2):
        raise RuntimeError("offline renewal probe must distinguish one completed refresh from requested successive refreshes")
    if evidence.get("commitment_txid") != refresh["commitment_txid"]:
        raise RuntimeError("offline renewal probe observed a different completed commitment")
    if not isinstance(evidence.get("replacement_outpoint"), str) or not re.fullmatch(r"[0-9a-f]{64}:[0-9]+", evidence["replacement_outpoint"]):
        raise RuntimeError("offline renewal probe lacks the completed replacement")
    if not isinstance(evidence.get("blocked_reason"), str) or not evidence["blocked_reason"].strip():
        raise RuntimeError("offline renewal probe lacks an observed reason")
    checks = evidence.get("checks")
    rejections = evidence.get("rejections")
    if not isinstance(checks, dict) or set(checks) != OFFLINE_RENEWAL_CHECKS or any(value is not True for value in checks.values()):
        raise RuntimeError("offline renewal boundary checks did not all pass")
    if not isinstance(rejections, dict) or set(rejections) != OFFLINE_RENEWAL_REJECTIONS or any(not isinstance(value, str) or not value.strip() for value in rejections.values()):
        raise RuntimeError("offline renewal probe must observe both real registration rejections")
    return evidence


def acceptance(run, binaries=None, backup_outage=False, refresh_count=1):
    if type(refresh_count) is not int or not 1 <= refresh_count <= 10 or (backup_outage and refresh_count > 1):
        raise ValueError("live refresh count must be 1..10 and cannot combine repeated refreshes with backup outage")
    run.live_refresh_summary = {"requested_refresh_count": refresh_count, "completed_refresh_count": 0}
    # All wallet operations are real Go SDK calls; run separate preparation and
    # restoration processes, retaining only the mnemonic between them.
    if binaries:
        for name in BINARIES:
            shutil.copy2(binaries / name, run.directory / name)
        manifest = binaries / "build-manifest.json"
        supplied = json.loads(manifest.read_text()) if manifest.exists() else None
    else:
        run.command("live-build-backup", ["cargo", "build", "--locked", "--bin", "backup-server"], BACKUP)
        run.command("live-build-fulmine", ["go","build","-o",str(run.directory/"fulmine"),"./cmd/fulmine"], FULMINE)
        run.command("live-build-client", ["go","build","-o",str(run.directory/"recovery-client"),"./cmd/recovery-client"], FULMINE)
        run.command("live-build-tests", ["go","test","-c","-o",str(run.directory/"recovery-tests"),"./pkg/recovery"], FULMINE)
        shutil.copy2(BACKUP/"target/debug/backup-server", run.directory/"backup-server")
        supplied = binary_manifest(run.directory)
        supplied["sources"] = {name: run.command("source-"+name, ["git", "rev-parse", "HEAD"], root).strip() for name, root in (("fulmine", FULMINE), ("backup", BACKUP))}
        run.source_worktree_dirty = {name: bool(run.command("source-dirty-"+name, ["git", "status", "--porcelain"], root).strip()) for name, root in (("fulmine", FULMINE), ("backup", BACKUP))}
    run.build_manifest = binary_manifest(run.directory, supplied)
    if hasattr(run, "source_worktree_dirty"):
        run.build_manifest["source_worktree_dirty"] = run.source_worktree_dirty
    (run.directory/"build-manifest.json").write_text(json.dumps(run.build_manifest, indent=2)+"\n")
    stack = Stack(run)
    def fixture(name, timeout, env):
        log = run.command(name, [str(run.directory/"recovery-tests"), "-test.v", f"-test.run=^{name}$", f"-test.timeout={timeout}s"], env=env, timeout=timeout+10)
        statuses = re.findall(r"^--- (PASS|FAIL|SKIP): " + re.escape(name) + r"\s", log, re.MULTILINE)
        if statuses != ["PASS"]:
            raise RuntimeError("required live fixture did not run and pass: " + name)
    try:
        fixture("TestLiveBullNostrDerivation", 10, run.env)
        stack.compose("up", "-d", "--pull", "never", "bitcoin", timeout=180)
        stack.bitcoin = stack.endpoint("bitcoin",18443)
        wait_for("Bitcoin",lambda: stack.rpc("getblockchaininfo"))
        info=stack.rpc("getblockchaininfo")
        if info["chain"] != "regtest" or info["blocks"] != 0: raise RuntimeError("live chain is not fresh regtest")
        stack.rpc("createwallet",["faucet"])
        stack.mining_address=stack.rpc("getnewaddress",wallet="/wallet/faucet")
        stack.mine(110)
        stack.compose("up", "-d", "--pull", "never", "mempool_api", "nbxplorer", timeout=180)
        stack.compose("up", "-d", "--pull", "never", "arkd-wallet")
        wallet_endpoint=stack.endpoint("arkd-wallet",6060).removeprefix("http://")
        wallet_env=run.env.copy();wallet_env["RECOVERY_LIVE_WALLET"]=wallet_endpoint
        fixture("TestLiveWalletReady", 100, wallet_env)
        stack.compose("up", "-d", "--pull", "never", "arkd")
        ark=stack.endpoint("arkd",7070); admin=stack.endpoint("arkd",7071); explorer=stack.endpoint("mempool_api",8999)+"/api/v1"
        wait_for("arkd wallet",lambda:request(admin+"/v1/admin/wallet/status"))
        seed=request(admin+"/v1/admin/wallet/seed")["seed"]
        request(admin+"/v1/admin/wallet/create",{"seed":seed,"password":"secret"})
        del seed
        request(admin+"/v1/admin/wallet/unlock",{"password":"secret"})
        wait_for("arkd wallet sync",lambda:request(admin+"/v1/admin/wallet/status").get("synced"))
        address=request(admin+"/v1/admin/wallet/address")["address"]
        for _ in range(21): stack.rpc("sendtoaddress",[address,1],"/wallet/faucet")
        stack.mine()
        request(admin+"/v1/admin/intentFees",{"fees":{k:"0.0" for k in ["offchainInputFee","onchainInputFee","offchainOutputFee","onchainOutputFee"]}})
        ports=[free_port() for _ in range(5)]
        grpc_port,http_port,delegate_port,backup_port,storage_port=ports
        origin=f"http://127.0.0.1:{backup_port}"
        data=run.directory/"fulmine-data"
        publisher=run.command("live-publisher",[str(run.directory/"recovery-client"),"publisher","--out",str(data/"recovery-prototype"),"--origin",origin]).strip()
        backup_env = {key: value for key, value in run.env.items() if not key.startswith("BACKUP_SERVER_")}
        backup_env.update(BACKUP_SERVER_DB_PATH=str(run.directory/"backup.sqlite"),
            BACKUP_SERVER_BIND=f"127.0.0.1:{storage_port}",
            BACKUP_SERVER_MAX_LIVE_BYTES=str(256*1024*1024), BACKUP_SERVER_MAX_HEADS="128",
            BACKUP_SERVER_LIMITER_MAX_SUBJECTS="1000",
            BACKUP_SERVER_RECOVERY_ORIGIN=origin, BACKUP_SERVER_RECOVERY_PUBLISHER=publisher)
        backup = stack.process("live-backup",[str(run.directory/"backup-server"), "serve"], backup_env)
        stack.backup_proxy(backup_port, storage_port)
        wait_for("integrated backup proxy", lambda: request(origin+"/healthz"))
        env=run.env.copy()
        env["FULMINE_LOG_LEVEL"] = "5"
        env.update(FULMINE_DATADIR=str(data),FULMINE_GRPC_PORT=str(grpc_port),FULMINE_HTTP_PORT=str(http_port),FULMINE_DELEGATE_PORT=str(delegate_port),FULMINE_DELEGATE_ENABLED="true",FULMINE_DELEGATE_FEE="0",FULMINE_ARK_SERVER=ark,FULMINE_ESPLORA_URL=explorer,FULMINE_NO_MACAROONS="true",FULMINE_SCHEDULER_POLL_INTERVAL="1",FULMINE_DISABLE_TELEMETRY="true",FULMINE_RECOVERY_PROTOTYPE_URL=origin)
        delegate=stack.process("live-fulmine",[str(run.directory/"fulmine")],env)
        fulmine=f"http://127.0.0.1:{http_port}"
        wait_for("Fulmine",lambda:request(fulmine+"/api/v1/wallet/status"))
        mnemonic=request(fulmine+"/api/v1/wallet/genseed")["mnemonic"]
        request(fulmine+"/api/v1/wallet/create",{"mnemonic":mnemonic,"password":"password","server_url":ark})
        del mnemonic
        request(fulmine+"/api/v1/wallet/unlock",{"password":"password"})
        wait_for("Fulmine sync",lambda:request(fulmine+"/api/v1/wallet/status").get("synced"))
        config={"ark":ark,"admin":admin,"explorer":explorer,"delegate":f"127.0.0.1:{delegate_port}","backup":origin,"workdir":str(run.directory),"bitcoin":stack.bitcoin,"mining_address":stack.mining_address}
        config["public_test_mnemonic"] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        config_path=run.directory/"live-config.json";config_path.write_text(json.dumps(config))
        env=run.env.copy();env.update(RECOVERY_LIVE_CONFIG=str(config_path),RECOVERY_BITCOIN_RPC_URL=stack.bitcoin,RECOVERY_BITCOIN_RPC_USER="admin1",RECOVERY_BITCOIN_RPC_PASSWORD="123")
        fixture("TestLivePrepare", 150, env)
        # The preparation process has exited before refresh submission.
        protected=json.loads((run.directory/"protected-request.json").read_text())
        if backup_outage:
            backup.kill()
            backup.wait(timeout=5)
        request(f"http://127.0.0.1:{delegate_port}/v1/delegate",protected)
        if backup_outage:
            wait_for("failed protected refresh", lambda:failed_refresh(data, run.directory/"live-fulmine.log"), timeout=120)
            fixture("TestLiveOriginalUnspent", 30, env)
            (run.directory/"live-outage-evidence.json").write_text(json.dumps({"backup_process_killed":True,"candidate_retained":True,"task_status":"failed","forfeit_submissions":0,"original_vtxo_unspent":True}))
            return
        refresh = wait_for("completed protected refresh",lambda:completed_refresh(data, run.directory/"live-fulmine.log"),timeout=120)
        run.live_refresh_summary["completed_refresh_count"] = 1
        stack.mine()
        renewal = None
        saved_seed = None
        if refresh_count > 1:
            # The controller retains the public fixture's seed solely for later
            # restoration. No file or config input exposes it to the probe.
            saved_seed = (run.directory/"seed").read_bytes()
            (run.directory/"seed").unlink()
            shutil.rmtree(run.directory/"wallet")
            config.update(public_test_mnemonic="", requested_refresh_count=refresh_count,
                          completed_commitment_txid=refresh["commitment_txid"])
            config_path.write_text(json.dumps(config))
            fixture("TestLiveOfflineRenewalBoundary", 90, env)
            renewal = offline_renewal_evidence(run.directory/"offline-renewal-evidence.json", refresh_count, refresh)
            if completed_refresh(data, run.directory/"live-fulmine.log") != refresh:
                raise RuntimeError("renewal probe changed the completed task or created another task")
            run.live_refresh_summary.update(status="blocked", blocked_round=renewal["blocked_round"],
                                            blocked_reason=renewal["blocked_reason"])
        # Stop both the delegate and every Arkade/indexer process before restore.
        delegate.terminate();delegate.wait(timeout=10)
        stack.compose("stop","arkd","arkd-wallet","nbxplorer","fulcrum","mempool_api",timeout=45)
        for endpoint in (ark, explorer, f"http://127.0.0.1:{delegate_port}"):
            parsed = urllib.parse.urlsplit(endpoint)
            with socket.socket() as sock:
                sock.settimeout(2)
                if sock.connect_ex((parsed.hostname, parsed.port)) == 0:
                    raise RuntimeError("recovery dependency still accepts connections after shutdown")
        if saved_seed is None:
            shutil.rmtree(run.directory/"wallet")
        else:
            with open(run.directory/"seed", "wb", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
                stream.write(saved_seed)
            saved_seed = None
        fixture("TestLiveRestore", 120, env)
        evidence = json.loads((run.directory/"live-evidence.json").read_text())
        for field in ("commitment_txid", "ciphertext_sha256"):
            if evidence.get(field) != refresh[field]:
                raise RuntimeError("restoration differs from completed protected refresh: " + field)
        prepare = json.loads((run.directory/"prepare-evidence.json").read_text())
        if evidence.get("replacement_outpoint") == prepare["original_outpoint"]:
            raise RuntimeError("restoration exited the original VTXO")
        if renewal is not None and evidence.get("replacement_outpoint") != renewal["replacement_outpoint"]:
            raise RuntimeError("restoration differs from the offline renewal probe's last completed coin")
        if renewal is not None and evidence.get("confirmed") is not True:
            raise RuntimeError("last completed coin was not confirmed exited after the renewal boundary")
        evidence.update(refresh)
        evidence["ark_and_delegate_endpoints_unreachable"] = True
        evidence["wallet_state_removed"] = not (run.directory/"wallet").exists()
        (run.directory/"live-evidence.json").write_text(json.dumps(evidence, indent=2))
        run.live_refresh_summary["last_completed_exit_confirmed"] = evidence.get("confirmed") is True
        if renewal is not None:
            return (f"completed 1 of {refresh_count} requested offline refreshes; round 2 blocked: "
                    + renewal["blocked_reason"] + "; last completed replacement exited after Arkade shutdown")
    finally:
        import sys
        primary = sys.exc_info()[1]
        try:
            stack.close()
        except Exception as cleanup:
            if primary is None:
                raise
            if hasattr(primary, "add_note"):
                primary.add_note("Cleanup also failed: " + str(cleanup))
            (run.directory/"cleanup-error.txt").write_text(str(cleanup))
