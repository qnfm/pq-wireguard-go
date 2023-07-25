/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/base64"
)

const (
	NoisePublicKeySize    = 2249
	NoisePrivateKeySize   = 2289
	NoisePresharedKeySize = 32
	kem1Name              = "HQC-128"
	kem1CTSize            = 4481
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
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
