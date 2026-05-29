package tls

import (
	utls "github.com/refraction-networking/utls"
)

var safari17ID = utls.ClientHelloID{Client: "Custom", Version: "safari_17"}

func init() {
	customSpecFactories["safari_17"] = newSafari17Spec
	PresetFingerprints["safari_17"] = &safari17ID
}

// newSafari17Spec returns a fresh ClientHelloSpec modelled after a stock macOS
// CFNetwork ClientHello observed on the wire, with the X25519MLKEM768 hybrid
// key share entry omitted. Cipher suite values without a named constant in
// this utls version are emitted as raw IANA codepoints.
func newSafari17Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS10,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			0x009e,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			0x0067,
			0xc028,
			0x006b,
			0x00a3,
			0x009f,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			0xccaa,
			0xc0ad,
			0xc09f,
			0xc05d,
			0xc061,
			0xc057,
			0xc053,
			0x00a2,
			0xc0ac,
			0xc09e,
			0xc05c,
			0xc060,
			0xc056,
			0xc052,
			0xc024,
			0x006a,
			0xc023,
			0x0040,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			0x0039,
			0x0038,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			0x0033,
			0x0032,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			0xc09d,
			0xc051,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			0xc09c,
			0xc050,
			0x003d,
			0x003c,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x00, 0x01, 0x02}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveID(0x001e),
				utls.CurveP384,
				utls.CurveP521,
				utls.FakeCurveFFDHE2048,
				utls.FakeCurveFFDHE3072,
			}},
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 22},
			&utls.ExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.SignatureScheme(0x0905),
				utls.SignatureScheme(0x0906),
				utls.SignatureScheme(0x0904),
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.Ed25519,
				utls.SignatureScheme(0x0808),
				utls.SignatureScheme(0x081a),
				utls.SignatureScheme(0x081b),
				utls.SignatureScheme(0x081c),
				utls.SignatureScheme(0x0809),
				utls.SignatureScheme(0x080a),
				utls.SignatureScheme(0x080b),
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.SignatureScheme(0x0303),
				utls.SignatureScheme(0x0301),
				utls.SignatureScheme(0x0302),
				utls.SignatureScheme(0x0402),
				utls.SignatureScheme(0x0502),
				utls.SignatureScheme(0x0602),
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
		},
	}
}
