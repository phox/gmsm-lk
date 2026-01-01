package lk

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
)

// ErrInvalidPublicKey is returned when the public key is invalid.
var ErrInvalidPublicKey = errors.New("lk: invalid public key")

// PrivateKey is the master key to create the licenses. Keep it in a secure
// location.
type PrivateKey struct {
	sm2.PrivateKey
}

type pkContainer struct {
	Pub []byte
	D   *big.Int
}

// NewPrivateKey generates a new SM2 private key.
func NewPrivateKey() (*PrivateKey, error) {
	tmp, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{PrivateKey: *tmp}, nil
}

func (k *PrivateKey) toSM2() *sm2.PrivateKey {
	return &k.PrivateKey
}

// ToBytes transforms the private key to a []byte.
func (k PrivateKey) ToBytes() ([]byte, error) {
	// 使用未压缩格式序列化公钥 (04 || X || Y)
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04 // 未压缩格式标识
	k.PrivateKey.PublicKey.X.FillBytes(pubBytes[1:33])
	k.PrivateKey.PublicKey.Y.FillBytes(pubBytes[33:65])

	c := &pkContainer{
		Pub: pubBytes,
		D:   k.PrivateKey.D,
	}

	return toBytes(c)
}

// ToB64String transforms the private key to a base64 string.
func (k PrivateKey) ToB64String() (string, error) {
	b, err := k.ToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ToB32String transforms the private key to a base32 string.
func (k PrivateKey) ToB32String() (string, error) {
	b, err := k.ToBytes()
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

// ToHexString transforms the private key to a hexadecimal string
func (k PrivateKey) ToHexString() (string, error) {
	b, err := k.ToBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// PrivateKeyFromBytes returns a private key from a []byte.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	c := &pkContainer{}
	if err := fromBytes(c, b); err != nil {
		return nil, err
	}

	// 使用 sm2.NewPrivateKeyFromInt 创建私钥
	sm2Priv, err := sm2.NewPrivateKeyFromInt(c.D)
	if err != nil {
		return nil, err
	}

	// 验证公钥是否匹配
	expectedPub := make([]byte, 65)
	expectedPub[0] = 0x04
	sm2Priv.PublicKey.X.FillBytes(expectedPub[1:33])
	sm2Priv.PublicKey.Y.FillBytes(expectedPub[33:65])

	// 检查存储的公钥与计算出的公钥是否一致
	for i := range expectedPub {
		if expectedPub[i] != c.Pub[i] {
			return nil, ErrInvalidPublicKey
		}
	}

	return &PrivateKey{PrivateKey: *sm2Priv}, nil
}

// PrivateKeyFromB64String returns a private key from a base64 encoded
// string.
func PrivateKeyFromB64String(str string) (*PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromBytes(b)
}

// PrivateKeyFromB32String returns a private key from a base32 encoded
// string.
func PrivateKeyFromB32String(str string) (*PrivateKey, error) {
	b, err := base32.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromBytes(b)
}

// PrivateKeyFromHexString returns a private key from a hexadecimal encoded
// string.
func PrivateKeyFromHexString(str string) (*PrivateKey, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromBytes(b)
}

// GetPublicKey returns the PublicKey associated with the private key.
func (k PrivateKey) GetPublicKey() *PublicKey {
	return &PublicKey{
		X: new(big.Int).Set(k.PrivateKey.PublicKey.X),
		Y: new(big.Int).Set(k.PrivateKey.PublicKey.Y),
	}
}

// PublicKey is used to check the validity of the licenses. You can share it
// freely. It uses SM2 curve (sm2p256v1).
type PublicKey struct {
	X *big.Int
	Y *big.Int
}

// ToBytes transforms the public key to a []byte.
func (k PublicKey) ToBytes() []byte {
	// 使用未压缩格式序列化公钥 (04 || X || Y)
	pkBytes := make([]byte, 65)
	pkBytes[0] = 0x04 // 未压缩格式标识
	k.X.FillBytes(pkBytes[1:33])
	k.Y.FillBytes(pkBytes[33:65])

	return pkBytes
}

// ToB64String transforms the public key to a base64 string.
func (k PublicKey) ToB64String() string {
	return base64.StdEncoding.EncodeToString(
		k.ToBytes(),
	)
}

// ToB32String transforms the public key to a base32 string.
func (k PublicKey) ToB32String() string {
	return base32.StdEncoding.EncodeToString(
		k.ToBytes(),
	)
}

// ToHexString transforms the public key to a hexadecimal string.
func (k PublicKey) ToHexString() string {
	return hex.EncodeToString(
		k.ToBytes(),
	)
}

// PublicKeyFromBytes returns a public key from a []byte.
// 支持未压缩格式 (04 || X || Y) 的公钥
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, ErrInvalidPublicKey
	}

	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	// 使用 sm2.P256() 验证点是否在曲线上
	curve := sm2.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{
		X: x,
		Y: y,
	}, nil
}

// PublicKeyFromB64String returns a public key from a base64 encoded
// string.
func PublicKeyFromB64String(str string) (*PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(b)
}

// PublicKeyFromB32String returns a public key from a base32 encoded
// string.
func PublicKeyFromB32String(str string) (*PublicKey, error) {
	b, err := base32.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(b)
}

// PublicKeyFromHexString returns a public key from a hexadecimal encoded
// string.
func PublicKeyFromHexString(str string) (*PublicKey, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(b)
}
