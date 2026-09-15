// Package fixtures holds the shared, public recovery protocol conformance vector.
package fixtures

import _ "embed"

// WireV1 contains public synthetic keys; never use them for funds.
//
//go:embed recovery-wire-v1.json
var WireV1 []byte

const WireV1SHA256 = "4ce1053bb849e7bc0db7cd3702c1f623dcea5d60e45853ac1b5c4e0c224092c8"
