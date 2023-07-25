/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/ntruprime/sntrup653"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	// "golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/tai64n"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 2*4 + sntrup653.PublicKeySize + chacha20poly1305.Overhead + sntrup653.CiphertextSize + blake2s.Size + chacha20poly1305.Overhead + tai64n.TimestampSize + chacha20poly1305.Overhead + 2*blake2s.Size128 // size of handshake initiation message
	MessageResponseSize        = 3*4 + 2*sntrup653.CiphertextSize + chacha20poly1305.Overhead + 2*blake2s.Size128                                                                                                                       // size of response message
	MessageCookieReplySize     = 64                                                                                                                                                                                                     // size of cookie reply message
	MessageTransportHeaderSize = 16                                                                                                                                                                                                     // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + chacha20poly1305.Overhead                                                                                                                                                 // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                                                                                                                                                                                   // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                                                                                                                                                                                  // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type        uint32
	Sender      uint32
	Ephemeral   [NoisePublicKeySize + chacha20poly1305.Overhead]byte
	CipherTextS [sntrup653.CiphertextSize]byte //Server Static Encapsulation
	Static      [blake2s.Size + chacha20poly1305.Overhead]byte
	Timestamp   [tai64n.TimestampSize + chacha20poly1305.Overhead]byte
	MAC1        [blake2s.Size128]byte
	MAC2        [blake2s.Size128]byte
}

type MessageResponse struct {
	Type        uint32
	Sender      uint32
	Receiver    uint32
	CipherTextE [sntrup653.CiphertextSize]byte                             //Client Ephemeral Encapsulation
	CipherTextC [sntrup653.CiphertextSize + chacha20poly1305.Overhead]byte //Client Static Encapsulation
	MAC1        [blake2s.Size128]byte
	MAC2        [blake2s.Size128]byte
	// Ephemeral NoisePublicKey

}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + chacha20poly1305.Overhead]byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte // hash value
	chainKey                  [blake2s.Size]byte // chain key
	presharedKey              NoisePresharedKey  // H(pkSC[:16]^pkSS[:16])
	localEphemeral            NoisePrivateKey    // ephemeral secret key
	localIndex                uint32             // used to clear hash-table
	remoteIndex               uint32             // index for sending
	remoteStatic              NoisePublicKey     // long term key
	remoteEphemeral           NoisePublicKey     // ephemeral public key
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
	// precomputedStaticStatic   [NoisePublicKeySize]byte // precomputed shared secret

}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

// Sender (S):
//     Role of entity that sends an encrypted message.
// Recipient (R):
//     Role of entity that receives an encrypted message.
// Ephemeral (E):
//     Role of a fresh random value meant for one-time use.
// SerializePrivateKey(skX): Produce a byte string of length Nsk encoding the private key skX.
// DeserializePrivateKey(skXm): Parse a byte string of length Nsk to recover a private key. This function can raise a DeserializeError error upon skXm deserialization failure.

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	// handshake.localEphemeral, err = newPrivateKey()
	pkE, skE, err := sntrup653.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	skEm, err := skE.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pkEm, err := pkE.MarshalBinary()
	if err != nil {
		return nil, err
	}
	handshake.localEphemeral = NoisePrivateKey(skEm)
	handshake.mixHash(handshake.remoteStatic[:])

	//Encapsulation
	pkR, err := sntrup653.Scheme().UnmarshalBinaryPublicKey(handshake.remoteStatic[:])
	if err != nil {
		return nil, err
	}

	ctR, ssR, err := pkR.Scheme().Encapsulate(pkR)
	if err != nil {
		return nil, err
	}

	// handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:        MessageInitiationType,
		CipherTextS: [sntrup653.CiphertextSize]byte(ctR),
	}

	// ae, err := chacha20poly1305.New(ss[:])
	// ae.Seal(msg.Ephemeral[:], ZeroNonce[:], pkEm, nil)

	// handshake.mixKey(msg.Ephemeral[:])
	// handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(ctR[:])
	handshake.mixHash(ctR[:])

	// ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	// if err != nil {
	// 	return nil, err
	// }
	var key [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], ssR[:])
	// encrypt ephemeral key
	aead, _ := chacha20poly1305.New(key[:])
	hpki := blake2s.Sum256(device.staticIdentity.publicKey[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], hpki[:], handshake.hash[:])
	// handshake.mixHash(msg.Static[:])

	KDF1(&key, handshake.chainKey[:], msg.Static[blake2s.Size:blake2s.Size+chacha20poly1305.Overhead])
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Ephemeral[:0], ZeroNonce[:], pkEm[:], handshake.hash[:])
	// encrypt timestamp
	// if isZero(handshake.precomputedStaticStatic[:]) {
	// 	return nil, errInvalidPublicKey
	// }
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], handshake.presharedKey[:])
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.CipherTextS[:])
	mixKey(&chainKey, &InitialChainKey, msg.CipherTextS[:])

	// decrypt the hash of static key
	var hpeerPK [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	var pkCE NoisePublicKey
	skSm, err := sntrup653.Scheme().UnmarshalBinaryPrivateKey(device.staticIdentity.privateKey[:])
	if err != nil {
		return nil
	}
	ssS, err := sntrup653.Scheme().Decapsulate(skSm, msg.CipherTextS[:])
	if err != nil {
		return nil
	}

	// ss, err := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
	// if err != nil {
	// 	return nil
	// }
	KDF2(&chainKey, &key, chainKey[:], ssS[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(hpeerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		println("Static AEAD not ok")
		return nil
	}
	// mixHash(&hash, &hash, msg.Static[:])

	// decrypt ephemeral public key
	KDF1(&key, chainKey[:], msg.Static[blake2s.Size:blake2s.Size+chacha20poly1305.Overhead])
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(pkCE[:0], ZeroNonce[:], msg.Ephemeral[:], hash[:])
	if err != nil {
		println("Ephemeral Client public key AEAD not ok")
		return nil
	}
	// lookup peer

	peer := device.LookupPeer(hpeerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	// if isZero(handshake.precomputedStaticStatic[:]) {
	// 	handshake.mutex.RUnlock()
	// 	return nil
	// }
	KDF2(&chainKey, &key, chainKey[:], handshake.presharedKey[:])
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = pkCE
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key
	pkEm, err := sntrup653.Scheme().UnmarshalBinaryPublicKey(handshake.remoteEphemeral[:])
	if err != nil {
		return nil, err
	}
	ctE, ssE, err := pkEm.Scheme().Encapsulate(pkEm)
	// handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.CipherTextE = [sntrup653.CiphertextSize]byte(ctE)

	pkCm, err := sntrup653.Scheme().UnmarshalBinaryPublicKey(handshake.remoteStatic[:])
	if err != nil {
		return nil, err
	}
	ctC, ssC, err := sntrup653.Scheme().Encapsulate(pkCm)
	if err != nil {
		return nil, err
	}
	// msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(ctE[:])
	// handshake.mixHash(ctC)
	// handshake.mixKey(ctC)

	handshake.mixKey(ssE[:])

	// ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
	// if err != nil {
	// 	return nil, err
	// }
	// handshake.mixKey(ss[:])
	// ss, err = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	// if err != nil {
	// 	return nil, err
	// }
	// handshake.mixKey(ss[:])

	// add preshared key

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.CipherTextC[:0], ZeroNonce[:], ctC[:], handshake.hash[:])
	handshake.mixHash(msg.CipherTextC[:])
	handshake.mixKey(ssC[:])

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {
		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH
		skEm, err := sntrup653.Scheme().UnmarshalBinaryPrivateKey(handshake.localEphemeral[:])
		if err != nil {
			return false
		}
		ssE, err := skEm.Scheme().Decapsulate(skEm, msg.CipherTextE[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &handshake.hash, msg.CipherTextE[:])
		// mixHash(&hash, &handshake.hash, msg.CipherTextC[:])
		// mixKey(&chainKey, &handshake.chainKey, msg.CipherTextC[:])
		mixKey(&chainKey, &handshake.chainKey, ssE[:])

		// ss, err := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
		// if err != nil {
		// 	return false
		// }
		// mixKey(&chainKey, &chainKey, ss[:])
		setZero(ssE[:])

		// ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
		// if err != nil {
		// 	return false
		// }
		// mixKey(&chainKey, &chainKey, ss[:])
		// setZero(ss[:])

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		var ctC [sntrup653.CiphertextSize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript

		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(ctC[:0], ZeroNonce[:], msg.CipherTextC[:], hash[:])
		if err != nil {
			println("CipherTextC AEAD not ok")
			return false
		}
		skCm, err := sntrup653.Scheme().UnmarshalBinaryPrivateKey(device.staticIdentity.privateKey[:])
		if err != nil {
			return false
		}
		ssC, err := skCm.Scheme().Decapsulate(skCm, ctC[:])
		if err != nil {
			println("ssC Decap not ok")
			return false
		}
		mixHash(&hash, &hash, msg.CipherTextC[:])
		mixKey(&chainKey, &chainKey, ssC[:])

		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next.Load()
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.next.Store(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next.Store(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.next.Load()
	keypairs.next.Store(nil)
	return true
}
