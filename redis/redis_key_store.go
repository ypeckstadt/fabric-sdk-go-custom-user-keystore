package redis

import (
	"encoding/hex"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/ypeckstadt/fabric-sdk-go-custom-user-keystore/hyperledger/fabric/bccsp"
)

// RedisKeyStore is in-memory implementation of BCCSP key store
type RedisKeyStore struct {
	store    map[string]bccsp.Key
	password []byte
	client *redis.Client
}

// NewRedisKeyStore creates a new RedisKeyStore instance
func NewRedisKeyStore(password []byte, client *redis.Client) *RedisKeyStore {
	store := make(map[string]bccsp.Key)
	return &RedisKeyStore{store: store, password: password, client:client}
}

// ReadOnly returns always false
func (s *RedisKeyStore) ReadOnly() bool {
	return false
}

// GetKey returns a key for the provided SKI
func (s *RedisKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	key, ok := s.store[hex.EncodeToString(ski)]
	if !ok {
		return nil, fmt.Errorf("Key not found [%s]", ski)
	}
	return key, nil
}

// StoreKey stores a key
func (s *RedisKeyStore) StoreKey(key bccsp.Key) error {
	ski := hex.EncodeToString(key.SKI())
	s.store[ski] = key
	err := s.client.Set(ski, "save the key", 0).Err()
	if err != nil {
		return err
	}
	return nil
}
