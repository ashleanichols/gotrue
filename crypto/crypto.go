package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/netlify/gotrue/conf"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type passphrase struct {
	Value string `envconfig:"passphrase"`
}

// SecureToken creates a new random token
func SecureToken() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err.Error()) // rand should never fail
	}
	return removePadding(base64.URLEncoding.EncodeToString(b))
}

func removePadding(token string) string {
	return strings.TrimRight(token, "=")
}

// Generate key used to encrypt totp secret
func getEncryptionKey() string {
	passphrase := &passphrase{}
	err := envconfig.Process("gotrue", passphrase)
	if err != nil {
		panic(fmt.Errorf("GOTRUE_PASSPHRASE not found: %v", err))
	}
	hasher := md5.New()
	hasher.Write([]byte(passphrase.Value))
	return hex.EncodeToString(hasher.Sum(nil))
}

// EncryptTotpUrl takes in a url and encrypts it with a passphrase
func EncryptTotpUrl(url []byte) []byte {
	key := getEncryptionKey()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	encryptedSecret := aesGCM.Seal(nonce, nonce, url, nil)
	return encryptedSecret
}

// DecryptTotpUrl uses the passphrase to decrypt a url
func DecryptTotpUrl(encryptedUrl []byte) (string, error) {
	key := getEncryptionKey()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := encryptedUrl[:nonceSize], encryptedUrl[nonceSize:]
	secret, err := aesGCM.Open(nil, nonce, ciphertext, nil)

	return string(secret), err
}

// GenerateTotpKey returns a key based on the config and user's accountName
// which is either an email or phone number.
func GenerateTotpKey(conf *conf.Configuration, accountName string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      conf.SiteURL,
		AccountName: accountName,
		Algorithm:   otp.AlgorithmSHA256,
	})
	return key, err
}

// GenerateOtp returns a 6 digit otp based on a totp secret and a timestamp
func GenerateOtp(secret string, timestamp *time.Time, expiry uint) (string, error) {
	otp, err := totp.GenerateCodeCustom(secret, *timestamp, totp.ValidateOpts{
		Period:    expiry,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	return otp, err
}
