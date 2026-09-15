"""Report edge-case coverage from executed tests, never from case declarations."""
import json
import re
from pathlib import Path


def report(directory):
    observed = {}
    def record(name, status):
        # Repetition must never hide an earlier failure or skipped execution.
        rank = {"pass": 0, "skip": 1, "fail": 2}
        if name not in observed or rank[status] > rank[observed[name]]:
            observed[name] = status
    for path in directory.glob("*.log"):
        if path.stat().st_size > 16 * 1024 * 1024:
            continue
        for line in path.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                event = None
            if isinstance(event, dict) and event.get("Test") and event.get("Action") in {"pass", "fail", "skip"}:
                record(event["Test"], event["Action"])
            go_match = re.match(r"--- (PASS|FAIL|SKIP): (\S+)", line.strip())
            if go_match:
                record(go_match[2], {"PASS":"pass", "FAIL":"fail", "SKIP":"skip"}[go_match[1]])
            match = re.fullmatch(r"test (\S+) \.\.\. (ok|FAILED|ignored)", line)
            if match:
                record(match[1], {"ok":"pass", "FAILED":"fail", "ignored":"skip"}[match[2]])
    cases = json.loads((Path(__file__).parent / "edge-cases.json").read_text())
    rows = []
    for case in cases:
        statuses = [observed.get(test, "not_run") for test in case["tests"]]
        status = "unimplemented" if not statuses else ("failed" if "fail" in statuses else "passed" if all(v == "pass" for v in statuses) else "not_run")
        rows.append({**case, "status":status})
    return {"scope":"bounded failure matrix; not exhaustive or a security proof", "cases":rows}
