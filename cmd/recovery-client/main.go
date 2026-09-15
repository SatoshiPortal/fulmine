// recovery-client is a local, regtest prototype tool, not a wallet replacement.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	delegatev1 "github.com/ArkLabsHQ/fulmine/api-spec/protobuf/gen/go/delegate/v1"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func readKey(path string) (*btcec.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("key file must contain 32-byte hex")
	}
	defer clear(b)
	key, _ := btcec.PrivKeyFromBytes(b)
	if key.Key.IsZero() || hex.EncodeToString(key.Serialize()) != hex.EncodeToString(b) {
		return nil, fmt.Errorf("invalid private key")
	}
	return key, nil
}
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: recovery-client keygen|register|fetch [flags]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	keyFile := flags.String("key-file", "", "Nostr private key hex file (test identity)")
	arkFile := flags.String("ark-key-file", "", "Ark input-owner private key file; defaults to key-file")
	origin := flags.String("origin", "", "backup origin")
	publisher := flags.String("publisher", "", "publisher x-only public key from delegate info")
	input := flags.String("request", "", "existing delegate request JSON")
	outputs := flags.String("outputs", "", "JSON array of replacement output metadata")
	output := flags.String("out", "", "output file for register, or directory for fetch")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if command == "publisher" {
		if *output == "" || *origin == "" {
			return fmt.Errorf("publisher requires out directory and origin")
		}
		m, err := recovery.NewManager(*output, *origin)
		if err != nil {
			return err
		}
		defer m.Close()
		fmt.Println(m.Public())
		return nil
	}
	if *keyFile == "" {
		return fmt.Errorf("key-file is required")
	}
	if command == "keygen" {
		key, err := btcec.NewPrivateKey()
		if err != nil {
			return err
		}
		defer key.Zero()
		if err = writePrivate(*keyFile, []byte(hex.EncodeToString(key.Serialize())+"\n")); err != nil {
			return err
		}
		fmt.Println(recovery.Public(key))
		return nil
	}
	owner, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	defer owner.Zero()
	switch command {
	case "register":
		if *input == "" || *outputs == "" || *output == "" || *publisher == "" || *origin == "" {
			return fmt.Errorf("register requires request, outputs, out, publisher, origin")
		}
		data, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		var request delegatev1.DelegateRequest
		if err = protojson.Unmarshal(data, &request); err != nil {
			return err
		}
		if request.Intent == nil {
			return fmt.Errorf("intent required")
		}
		var message intent.RegisterMessage
		if err = message.Decode(request.Intent.Message); err != nil {
			return err
		}
		canonicalMessage, err := message.Encode()
		if err != nil {
			return err
		}
		proof, err := psbt.NewFromRawBytes(strings.NewReader(request.Intent.Proof), true)
		if err != nil {
			return err
		}
		canonicalProof, err := proof.B64Encode()
		if err != nil {
			return err
		}
		metadata, err := os.ReadFile(*outputs)
		if err != nil {
			return err
		}
		var out []recovery.Output
		if err = json.Unmarshal(metadata, &out); err != nil {
			return err
		}
		id, err := btcec.NewPrivateKey()
		if err != nil {
			return err
		}
		grantID := recovery.Hash(id.Serialize())
		id.Zero()
		now := uint64(time.Now().Unix())
		grant := recovery.Grant{Owner: recovery.Public(owner), Publisher: *publisher, Origin: *origin, ID: grantID, Scope: recovery.Scope(canonicalMessage, canonicalProof, out), ValidFrom: now - 60, ExpiresAt: now + 31*86400, MaxRecords: 16, MaxBytes: 2 * 1024 * 1024}
		grant.Signature, err = recovery.Sign(owner, grant.Digest())
		if err != nil {
			return err
		}
		signer := owner
		if *arkFile != "" {
			signer, err = readKey(*arkFile)
			if err != nil {
				return err
			}
			defer signer.Zero()
		}
		auth, err := recovery.Sign(signer, grant.Digest())
		if err != nil {
			return err
		}
		registration := recovery.Registration{Grant: grant, Outputs: out, OwnerSignatures: map[string]string{recovery.Public(signer): auth}}
		encoded, err := json.Marshal(registration)
		if err != nil {
			return err
		}
		request.RecoveryRegistration = string(encoded)
		data, err = protojson.MarshalOptions{Indent: "  "}.Marshal(&request)
		if err != nil {
			return err
		}
		return writePrivate(*output, data)
	case "fetch":
		if *output == "" || *origin == "" {
			return fmt.Errorf("fetch requires out directory and origin")
		}
		count, err := recovery.FetchToDirectory(context.Background(), *origin, owner, *output)
		if err != nil {
			return err
		}
		fmt.Printf("Recovered %d authenticated candidate bundles; snapshot fetch complete, Bitcoin state still requires verification.\n", count)
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}
