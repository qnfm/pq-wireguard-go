/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func assertBNil(b *testing.B, err error) {
	if err != nil {
		b.Fatal(err)
	}
}

func randBDevice(b *testing.B) *Device {
	kemName := "BIKE-L1"
	kem := oqs.KeyEncapsulation{}
	defer kem.Clean() // clean up even in case of panic
	assertBNil(b, kem.Init(kemName, nil))

	pk, err := kem.GenerateKeyPair()
	assertBNil(b, err)
	sk := kem.ExportSecretKey()
	assertBNil(b, err)

	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey([NoisePrivateKeySize]byte(sk), [NoisePublicKeySize]byte(pk))
	return device
}

func BenchmarkHandshakeServer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dev1 := randBDevice(b)
		dev2 := randBDevice(b)

		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		peer1.Start()
		peer2.Start()

		msg1, _ := dev1.CreateMessageInitiation(peer2)

		packet := make([]byte, 0, MessageInitiationSize)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)
		//Server side
		b.StartTimer()
		dev2.ConsumeMessageInitiation(msg1)
		msg2, _ := dev2.CreateMessageResponse(peer1)
		b.StopTimer()
		//end
		dev1.ConsumeMessageResponse(msg2)
		dev1.Close()
		dev2.Close()
		b.StartTimer()
	}
}

func BenchmarkHandshakeClient(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dev1 := randBDevice(b)
		dev2 := randBDevice(b)

		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		peer1.Start()
		peer2.Start()
		//Client side
		b.StartTimer()
		msg1, _ := dev1.CreateMessageInitiation(peer2)
		b.StopTimer()
		//end
		packet := make([]byte, 0, MessageInitiationSize)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)

		dev2.ConsumeMessageInitiation(msg1)
		msg2, _ := dev2.CreateMessageResponse(peer1)

		//Client side
		b.StartTimer()
		dev1.ConsumeMessageResponse(msg2)
		b.StopTimer()
		//end

		dev1.Close()
		dev2.Close()
		b.StartTimer()
	}
}

func BenchmarkHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dev1 := randBDevice(b)
		dev2 := randBDevice(b)

		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)

		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		peer1.Start()
		peer2.Start()
		/* simulate handshake */
		b.StartTimer()
		// initiation message

		msg1, _ := dev1.CreateMessageInitiation(peer2)

		packet := make([]byte, 0, MessageInitiationSize)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)
		dev2.ConsumeMessageInitiation(msg1)
		// response message

		msg2, _ := dev2.CreateMessageResponse(peer1)

		dev1.ConsumeMessageResponse(msg2)
		b.StopTimer()
		// key pairs

		// peer1.BeginSymmetricSession()
		// assertBNil(b, err)

		// peer2.BeginSymmetricSession()
		// assertBNil(b, err)

		/** can't code test but manualy tested and ok
		assertEqual(
			t,
			peer1.keypairs.next.send,
			peer2.keypairs.Current().receive)**/

		// key1 := peer1.keypairs.next.Load()
		// key2 := peer2.keypairs.current

		// // encrypting / decryption test
		// b.StopTimer()
		// func() {
		// 	testMsg := []byte("wireguard test message 1")
		// 	var out []byte
		// 	var nonce [12]byte
		// 	out = key1.send.Seal(nil, nonce[:], testMsg, nil)
		// 	d, err := key2.receive.Open(out[:0], nonce[:], out, nil)
		// 	assertBNil(b, err)
		// 	assertBEqual(b, testMsg[:], d[:])
		// }()

		// func() {
		// 	testMsg := []byte("wireguard test message 2")
		// 	var out []byte
		// 	var nonce [12]byte
		// 	out = key2.send.Seal(out, nonce[:], testMsg, nil)
		// 	out, err := key1.receive.Open(out[:0], nonce[:], out, nil)
		// 	assertBNil(b, err)
		// 	assertBEqual(b, testMsg, out)

		// }()
		dev1.Close()
		dev2.Close()
		b.StartTimer()
	}
}

func TestNoiseHanshakeSizes(t *testing.T) {
	fmt.Printf("Message init size %v bytes, message response size %+v bytes\n", MessageInitiationSize, MessageResponseSize)
}

func TestKem(t *testing.T) {
	kemName := "BIKE-L1"
	kem1 := oqs.KeyEncapsulation{}
	defer kem1.Clean() // clean up even in case of panic
	assertNil(t, kem1.Init(kemName, nil))

	pk1, err := kem1.GenerateKeyPair()
	assertNil(t, err)
	// sk1 := kem1.ExportSecretKey()
	assertNil(t, err)

	kem2 := oqs.KeyEncapsulation{}
	defer kem2.Clean() // clean up even in case of panic
	assertNil(t, kem2.Init(kemName, nil))

	pk2, err := kem2.GenerateKeyPair()
	assertNil(t, err)
	// sk2 := kem2.ExportSecretKey()
	assertNil(t, err)

	ct1, ss1, err1 := kem2.EncapSecret(pk1)
	ss1d, err2 := kem1.DecapSecret(ct1)

	ct2, ss2, err3 := kem1.EncapSecret(pk2)
	ss2d, err4 := kem2.DecapSecret(ct2)

	if !bytes.Equal(ss1, ss1d) || !bytes.Equal(ss2, ss2d) || err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randDevice(t *testing.T) *Device {
	kemName := "BIKE-L1"
	kem := oqs.KeyEncapsulation{}
	defer kem.Clean() // clean up even in case of panic
	assertNil(t, kem.Init(kemName, nil))

	pk, err := kem.GenerateKeyPair()
	assertNil(t, err)
	sk := kem.ExportSecretKey()
	assertNil(t, err)

	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey([NoisePrivateKeySize]byte(sk), [NoisePublicKeySize]byte(pk))
	return device
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.publicKey)
	assertNil(t, err)

	peer2, err := dev1.NewPeer(dev2.staticIdentity.publicKey)
	assertNil(t, err)

	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.presharedKey[:],
		peer2.handshake.presharedKey[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 1048576)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}
