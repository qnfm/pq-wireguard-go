/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestKem(t *testing.T) {
	_, sk1, err := kyber512.Scheme().GenerateKeyPair()
	assertNil(t, err)

	_, sk2, err := kyber512.Scheme().GenerateKeyPair()
	assertNil(t, err)

	pk1 := sk1.Public()
	pk2 := sk2.Public()

	ct1, ss1, err1 := kyber512.Scheme().Encapsulate(pk1)
	ss1d, err2 := kyber512.Scheme().Decapsulate(sk1, ct1)

	ct2, ss2, err3 := kyber512.Scheme().Encapsulate(pk2)
	ss2d, err4 := kyber512.Scheme().Decapsulate(sk2, ct2)

	if !bytes.Equal(ss1, ss1d) || !bytes.Equal(ss2, ss2d) || err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randDevice(t *testing.T) *Device {
	_, sk, err := kyber512.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	skM, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(NoisePrivateKey(skM))
	return device
}

func randDevice2(t *testing.B) *Device {
	_, sk, err := kyber512.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	skM, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(NoisePrivateKey(skM))
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

func BenchmarkHandshakeClient(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dev1 := randDevice2(b)
		dev2 := randDevice2(b)
		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		peer1.Start()
		peer2.Start()

		b.StartTimer()
		msg1, err := dev1.CreateMessageInitiation(peer2)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()

		peer := dev2.ConsumeMessageInitiation(msg1)
		if peer == nil {
			b.Fatal("handshake failed at initiation message")
		}
		msg2, err := dev2.CreateMessageResponse(peer1)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		peer = dev1.ConsumeMessageResponse(msg2)
		if peer == nil {
			b.Fatal("handshake failed at response message")
		}
		b.StopTimer()

		dev1.Close()
		dev2.Close()
	}
}

func BenchmarkHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {

		//ignore errors everywhere
		dev1 := randDevice2(b)
		dev2 := randDevice2(b)

		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		peer1.Start()
		peer2.Start()
		/* simulate handshake */

		// initiation message

		msg1, _ := dev1.CreateMessageInitiation(peer2)

		packet := make([]byte, 0, 4096)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)
		peer := dev2.ConsumeMessageInitiation(msg1)
		if peer == nil {
			b.Fatal("handshake failed at initiation message")
		}
		// response message

		msg2, _ := dev2.CreateMessageResponse(peer1)

		peer = dev1.ConsumeMessageResponse(msg2)
		if peer == nil {
			b.Fatal("handshake failed at response message")
		}
		// key pairs

		peer1.BeginSymmetricSession()

		peer2.BeginSymmetricSession()

		/** can't code test but manualy tested and ok
		assertEqual(
			t,
			peer1.keypairs.next.send,
			peer2.keypairs.Current().receive)**/

		key1 := peer1.keypairs.next.Load()
		key2 := peer2.keypairs.current

		// encrypting / decryption test

		func() {
			testMsg := []byte("wireguard test message 1")
			var out []byte
			var nonce [12]byte
			out = key1.send.Seal(out, nonce[:], testMsg, nil)
			out, _ = key2.receive.Open(out[:0], nonce[:], out, nil)
		}()

		func() {
			testMsg := []byte("wireguard test message 2")
			var out []byte
			var nonce [12]byte
			out = key2.send.Seal(out, nonce[:], testMsg, nil)
			out, _ = key1.receive.Open(out[:0], nonce[:], out, nil)
		}()
		dev1.Close()
		dev2.Close()
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.presharedKey[:],
		peer2.handshake.presharedKey[:],
	)

	if bytes.Equal(peer1.handshake.presharedKey[:], make([]byte, 32)) {
		t.Fatal("preshared nil")
	}
	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
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
