package tls

import (
	utls "github.com/refraction-networking/utls"
)

// customSpecFactories holds factories for ClientHelloSpec values that are not
// expressible via a built-in utls.ClientHelloID. Each factory must return a
// fresh spec on every call because uTLS mutates extension fields during
// ApplyPreset; a shared instance would skip key generation after first use.
var customSpecFactories = map[string]func() *utls.ClientHelloSpec{}

// ApplyCustomSpec installs a registered custom ClientHelloSpec on uconn when
// the active ClientHelloID matches a custom entry. It is a no-op otherwise.
// Must be called after utls.UClient and before BuildHandshakeState.
func ApplyCustomSpec(uconn *utls.UConn) error {
	if uconn == nil || uconn.ClientHelloID.Client != "Custom" {
		return nil
	}
	factory, ok := customSpecFactories[uconn.ClientHelloID.Version]
	if !ok {
		return nil
	}
	return uconn.ApplyPreset(factory())
}
