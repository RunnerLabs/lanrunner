package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const maxWire = 64 << 10 // hard ceiling on one encrypted frame

// hkdfSHA256 is RFC 5869 extract-then-expand. Implemented here so the whole
// program stays on the standard library — no module downloads, which matters
// when the machine has never touched the internet.
func hkdfSHA256(secret, salt, info []byte, n int) []byte {
	prk := hmacSum(salt, secret) // extract
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func hmacSum(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// secureConn wraps a TCP connection in AES-256-GCM with separate keys per
// direction and strictly increasing counter nonces.
//
// The counter nonce is what gives replay protection for free: a replayed,
// reordered, or injected frame decrypts against the wrong counter and fails
// authentication. There is no sequence-number heuristic to defeat.
type secureConn struct {
	c net.Conn
	r *bufio.Reader

	tx       cipher.AEAD
	rx       cipher.AEAD
	txPrefix [4]byte
	rxPrefix [4]byte

	wmu   sync.Mutex
	w     *bufio.Writer
	txCtr uint64

	rxCtr uint64
}

// deriveSession turns an ECDH shared secret into two directional keys.
// Both identities are mixed into the info string so a shared secret can never
// be reused across a different pair of peers (unknown key-share defence).
func deriveSession(shared, salt []byte, dialerFP, responderFP string, weAreDialer bool) *secureConn {
	base := fmt.Sprintf("lanrunner-v2|%s|%s", dialerFP, responderFP)
	d2r := hkdfSHA256(shared, salt, []byte(base+"|d2r"), 36)
	r2d := hkdfSHA256(shared, salt, []byte(base+"|r2d"), 36)

	txMat, rxMat := d2r, r2d
	if !weAreDialer {
		txMat, rxMat = r2d, d2r
	}

	sc := &secureConn{}
	txBlock, err := aes.NewCipher(txMat[:32])
	if err != nil {
		return nil
	}
	rxBlock, err := aes.NewCipher(rxMat[:32])
	if err != nil {
		return nil
	}
	if sc.tx, err = cipher.NewGCM(txBlock); err != nil {
		return nil
	}
	if sc.rx, err = cipher.NewGCM(rxBlock); err != nil {
		return nil
	}
	copy(sc.txPrefix[:], txMat[32:36])
	copy(sc.rxPrefix[:], rxMat[32:36])
	return sc
}

func (s *secureConn) attach(c net.Conn, r *bufio.Reader) {
	s.c = c
	s.r = r
	s.w = bufio.NewWriterSize(c, 8<<10)
}

func nonceFor(prefix [4]byte, ctr uint64) [12]byte {
	var n [12]byte
	copy(n[:4], prefix[:])
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// WriteFrame encrypts and writes one length-prefixed frame.
func (s *secureConn) WriteFrame(pt []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()

	nonce := nonceFor(s.txPrefix, s.txCtr)
	s.txCtr++
	ct := s.tx.Seal(nil, nonce[:], pt, nil)
	if len(ct) > maxWire {
		return fmt.Errorf("outbound frame %dB exceeds %dB ceiling", len(ct), maxWire)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if _, err := s.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	return s.w.Flush()
}

// ReadFrame reads and authenticates one frame. Only the read loop calls this,
// so rxCtr needs no lock.
func (s *secureConn) ReadFrame() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errors.New("zero-length frame")
	}
	if n > maxWire {
		return nil, fmt.Errorf("declared frame length %dB exceeds %dB ceiling", n, maxWire)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}
	nonce := nonceFor(s.rxPrefix, s.rxCtr)
	s.rxCtr++
	pt, err := s.rx.Open(nil, nonce[:], buf, nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD authentication failed at counter %d (tampered, replayed, or desynchronised)", s.rxCtr-1)
	}
	return pt, nil
}

func (s *secureConn) Close() error {
	if s.c == nil {
		return nil
	}
	return s.c.Close()
}
