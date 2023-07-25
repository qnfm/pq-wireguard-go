/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/base64"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/mceliece/mceliece348864f"
)

const (
	NoisePublicKeySize    = mceliece348864f.PublicKeySize
	NoisePrivateKeySize   = mceliece348864f.PrivateKeySize
	NoisePresharedKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoiseEPublicKey   [kyber512.PublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoiseEPrivateKey  [kyber512.PrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

// func loadExactHex(dst []byte, src string) error {
// 	slice, err := hex.DecodeString(src)
// 	if err != nil {
// 		return err
// 	}
// 	if len(slice) != len(dst) {
// 		return errors.New("hex string does not fit the slice")
// 	}
// 	copy(dst, slice)
// 	return nil
// }

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

// func (key *NoisePrivateKey) FromHex(src string) (err error) {
// 	err = loadExactHex(key[:], src)
// 	key.clamp()
// 	return
// }

// func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
// 	err = loadExactHex(key[:], src)
// 	if key.IsZero() {
// 		return
// 	}
// 	key.clamp()
// 	return
// }

func ToB64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func FromB64(dst []byte, src string) error {
	srcDec, err := base64.StdEncoding.DecodeString(src)
	copy(dst, srcDec)
	return err
}

// func (key *NoisePublicKey) FromHex(src string) error {
// 	return loadExactHex(key[:], src)
// }

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

// func (key *NoisePresharedKey) FromHex(src string) error {
// 	return loadExactHex(key[:], src)
// }
