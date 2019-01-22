package redis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"github.com/go-redis/redis"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"io"
)

// RedisUserStore is an implementation of UserStore for Redis
type RedisUserStore struct {
	client *redis.Client
	passphrase string
}

// NewRedisUserStore creates a new RedisUserStore instance
func NewRedisUserStore(client *redis.Client, passphrase string) *RedisUserStore {
	return &RedisUserStore{client:client, passphrase:passphrase}
}

// Store stores a user into store
func (s *RedisUserStore) Store(user *msp.UserData) error {
	key := user.ID+"@"+user.MSPID
	err := s.client.Set(s.createHash(key), s.encrypt(user.EnrollmentCertificate, s.passphrase), 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// Load loads a user from store
func (s *RedisUserStore) Load(id msp.IdentityIdentifier) (*msp.UserData, error) {
	key := id.ID+"@"+id.MSPID
	val, err := s.client.Get(s.createHash(key)).Result()
	if err == redis.Nil {
		return nil, msp.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	userData := msp.UserData{
		ID:                    id.ID,
		MSPID:                 id.MSPID,
		EnrollmentCertificate: s.decrypt([]byte(val), s.passphrase),
	}
	return &userData, nil
}

// encrypt encrypts data with passphrase
func (s *RedisUserStore) encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(s.createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decrypt decrypts data with passphrase
func (s *RedisUserStore) decrypt(data []byte, passphrase string) []byte {
	key := []byte(s.createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func (s *RedisUserStore) createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}
