//
// algorithms.go
//
// Copyright (c) 2018 Markku Rossi
//
// See the LICENSE file for the details on licensing.
//

package crypto

import (
	"fmt"
)

type EncType uint16

func (et EncType) String() string {
	info, ok := AlgorithmsByEncType[et]
	if ok {
		return info.Name
	}
	return fmt.Sprintf("{EncType 0x%x}", int(et))
}

type AlgorithmInfo struct {
	Name        string
	Aliases     []string
	Etype       EncType
	Description string
	RFC         string
}

var Algorithms = []*AlgorithmInfo{
	&AlgorithmInfo{
		Name:        "des-cbc-crc",
		Etype:       EncType(1),
		Description: "DES CBC mode with CRC-32",
		RFC:         "RFC 3961 section 6.2.3",
	},
	&AlgorithmInfo{
		Name:        "des-cbc-md4",
		Etype:       EncType(2),
		Description: "DES CBC mode with RSA-MD4",
		RFC:         "RFC 3961 section 6.2.2",
	},
	&AlgorithmInfo{
		Name:        "des-cbc-md5",
		Aliases:     []string{"des"},
		Etype:       EncType(3),
		Description: "DES CBC mode with RSA-MD5",
		RFC:         "RFC 3961 section 6.2.1",
	},
	&AlgorithmInfo{
		Name:        "des-cbc-raw",
		Etype:       EncType(4),
		Description: "DES CBC mode raw",
		RFC:         `RFC 3961 marked as "reserved"`,
	},
	&AlgorithmInfo{
		Name:        "des3-cbc-raw",
		Etype:       EncType(6),
		Description: "Triple DES CBC mode raw",
		RFC:         `RFC 3961 marked as "reserved"`,
	},
	&AlgorithmInfo{
		Name:        "des3-cbc-sha1",
		Aliases:     []string{"des3-hmac-sha1", "des3-cbc-sha1-kd"},
		Etype:       EncType(16),
		Description: "Triple DES CBC mode with HMAC/SHA1",
		RFC:         "RFC 3961, section 6.3",
	},
	&AlgorithmInfo{
		Name:        "aes128-cts-hmac-sha1-96",
		Aliases:     []string{"aes128-cts", "aes128-sha1"},
		Etype:       EncType(17),
		Description: "AES-128 CTS mode with 96-bit SHA-1 HMAC",
		RFC:         "RFC 3962",
	},
	&AlgorithmInfo{
		Name:        "aes256-cts-hmac-sha1-96",
		Aliases:     []string{"aes256-cts", "aes256-sha1"},
		Etype:       EncType(18),
		Description: "AES-256 CTS mode with 96-bit SHA-1 HMAC",
		RFC:         "RFC 3962",
	},
	&AlgorithmInfo{
		Name:        "aes128-cts-hmac-sha256-128",
		Aliases:     []string{"aes128-sha2"},
		Etype:       EncType(19),
		Description: "AES-128 CTS mode with 128-bit SHA-256 HMAC",
		RFC:         "RFC 3962",
	},
	&AlgorithmInfo{
		Name:        "aes256-cts-hmac-sha384-192",
		Aliases:     []string{"aes256-sha2"},
		Etype:       EncType(20),
		Description: "AES-256 CTS mode with 192-bit SHA-384 HMAC",
		RFC:         "RFC 3962",
	},
	&AlgorithmInfo{
		Name:        "arcfour-hmac",
		Aliases:     []string{"rc4-hmac", "arcfour-hmac-md5"},
		Etype:       EncType(23),
		Description: "Arcfour with HMAC/MD5",
		RFC:         "RFC 4757",
	},
	&AlgorithmInfo{
		Name:        "arcfour-hmac",
		Aliases:     []string{"rc4-hmac-exp", "arcfour-hmac-md5-exp"},
		Etype:       EncType(24),
		Description: "Exportable Arcfour with HMAC/MD5",
		RFC:         "RFC 4757",
	},
	&AlgorithmInfo{
		Name:        "camellia128-cts-cmac",
		Aliases:     []string{"camellia128-cts"},
		Etype:       EncType(25),
		Description: "Camellia-128 CTS mode with CMAC",
		RFC:         "RFC 4757",
	},
	&AlgorithmInfo{
		Name:        "camellia256-cts-cmac",
		Aliases:     []string{"camellia256-cts"},
		Etype:       EncType(26),
		Description: "Camellia-256 CTS mode with CMAC",
		RFC:         "RFC 4757",
	},
}

var AlgorithmsByEncType map[EncType]*AlgorithmInfo
var AlgorithmsByName map[string]*AlgorithmInfo

func init() {
	AlgorithmsByEncType = make(map[EncType]*AlgorithmInfo)
	AlgorithmsByName = make(map[string]*AlgorithmInfo)

	for _, alg := range Algorithms {
		// Algorithms by EncType value.
		AlgorithmsByEncType[alg.Etype] = alg

		// Algorithms by name and aliases.
		AlgorithmsByName[alg.Name] = alg
		for _, alias := range alg.Aliases {
			AlgorithmsByName[alias] = alg
		}
	}
}
