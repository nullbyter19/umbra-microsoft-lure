package main

import "encoding/base64"

// cfgMask is the XOR mask cmd/pack applies before base64-encoding each config
// value. It must match the constant in cmd/pack/main.go. Keeping the values
// obfuscated means the passphrase and server URL are not readable strings in
// the compiled beacon.
const cfgMask = "umbra::c2::2026::mask"

// unmask reverses mask(). A value that is not valid base64 is returned as-is,
// so a plaintext value still works during development.
func unmask(s string) string {
	if s == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	for i := range raw {
		raw[i] ^= cfgMask[i%len(cfgMask)]
	}
	return string(raw)
}
