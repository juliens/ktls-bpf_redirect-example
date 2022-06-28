package main

import (
	"crypto"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"net"
	"reflect"
	"syscall"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

// https://github.com/torvalds/linux/blob/v4.13/Documentation/networking/tls.txt

var dir_map = map[int]string{
	1: "TLX_TX",
	2: "TLS_RX",
}

const (
	TCP_ULP = 31
	SOL_TLS = 282
	TLS_TX  = 1
	TLS_RX  = 2

	kTLS_CIPHER_AES_GCM_128              = 51
	kTLS_CIPHER_AES_GCM_128_IV_SIZE      = 8
	kTLS_CIPHER_AES_GCM_128_KEY_SIZE     = 16
	kTLS_CIPHER_AES_GCM_128_SALT_SIZE    = 4
	kTLS_CIPHER_AES_GCM_128_TAG_SIZE     = 16
	kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE = 8

	kTLS_CIPHER_AES_GCM_256              = 52
	kTLS_CIPHER_AES_GCM_256_IV_SIZE      = 8
	kTLS_CIPHER_AES_GCM_256_KEY_SIZE     = 32
	kTLS_CIPHER_AES_GCM_256_SALT_SIZE    = 4
	kTLS_CIPHER_AES_GCM_256_TAG_SIZE     = 16
	kTLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE = 8

	kTLS_CIPHER_CHACHA20_POLY1305              = 54
	kTLS_CIPHER_CHACHA20_POLY1305_IV_SIZE      = 12
	kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE     = 32
	kTLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE    = 0
	kTLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE     = 16
	kTLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE = 8

	kTLSOverhead = 16
)

/* From linux/tls.h
struct tls_crypto_info {
	unsigned short version;
	unsigned short cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
}; */

type cipher_meta struct {
	Code     uint16
	KeySize  int
	IVSize   int
	SaltSize int
	Hash     func() hash.Hash
}

var ciphers_meta = map[uint16]cipher_meta{
	tls.TLS_AES_128_GCM_SHA256: {
		Code:     kTLS_CIPHER_AES_GCM_128,
		KeySize:  kTLS_CIPHER_AES_GCM_128_KEY_SIZE,
		IVSize:   kTLS_CIPHER_AES_GCM_128_IV_SIZE,
		SaltSize: kTLS_CIPHER_AES_GCM_128_SALT_SIZE,
		Hash:     crypto.SHA256.New,
	},
	tls.TLS_AES_256_GCM_SHA384: {
		Code:     kTLS_CIPHER_AES_GCM_256,
		KeySize:  kTLS_CIPHER_AES_GCM_256_KEY_SIZE,
		IVSize:   kTLS_CIPHER_AES_GCM_256_IV_SIZE,
		SaltSize: kTLS_CIPHER_AES_GCM_256_SALT_SIZE,
		Hash:     crypto.SHA384.New,
	},
	tls.TLS_CHACHA20_POLY1305_SHA256: {
		Code:     kTLS_CIPHER_CHACHA20_POLY1305,
		KeySize:  kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE,
		IVSize:   kTLS_CIPHER_CHACHA20_POLY1305_IV_SIZE,
		SaltSize: kTLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE,
		Hash:     crypto.SHA256.New,
	},
}

func kTLSEnable(c *net.TCPConn, s *tls.Conn, dir int) error {

	serverV := reflect.ValueOf(s)

	var halfConn reflect.Value
	switch dir {
	case TLS_TX:
		halfConn = serverV.Elem().FieldByName("out")
	case TLS_RX:
		halfConn = serverV.Elem().FieldByName("in")
	default:
		return fmt.Errorf("invalid direction: %d", dir)
	}

	trafficSecret := halfConn.FieldByName("trafficSecret").Bytes()
	seq := halfConn.FieldByName("seq").Slice(0, 8).Bytes()
	state := s.ConnectionState()

	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("wrong TLS version: %d", state.Version)
	}
	meta, ok := ciphers_meta[state.CipherSuite]
	if !ok {
		return fmt.Errorf("Wrong cipher %x", state.CipherSuite)
	}

	key := expandLabel(trafficSecret, "key", meta.KeySize, meta.Hash)
	iv := expandLabel(trafficSecret, "iv", meta.SaltSize+meta.IVSize, meta.Hash)

	cryptoInfoData := make([]byte, 4)

	binary.LittleEndian.PutUint16(cryptoInfoData, state.Version)
	binary.LittleEndian.PutUint16(cryptoInfoData[2:], meta.Code)

	// iv
	cryptoInfoData = append(cryptoInfoData, iv[meta.SaltSize:]...)
	// key
	cryptoInfoData = append(cryptoInfoData, key...)
	// salt
	cryptoInfoData = append(cryptoInfoData, iv[:meta.SaltSize]...)
	// seq
	cryptoInfoData = append(cryptoInfoData, seq[:]...)

	rwc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return rwc.Control(func(fd uintptr) {
		err = syscall.SetsockoptString(int(fd), SOL_TLS, dir, string(cryptoInfoData))
		if err != nil {
			log.Printf("kTLS: setsockopt(SOL_TLS, %s) failed: %v", dir_map[dir], err)
		}
	})
}

func expandLabel(secret []byte, label string, length int, new func() hash.Hash) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(nil)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(new, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
