package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"syscall"

	"github.com/golang/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"golang.org/x/term"
)

// Newer Vultisig apps (Android, iOS, web, extension) encrypt backups as
// "VLT\x02" || salt(16) || iv(12) || AES-256-GCM ciphertext, with the key derived by
// PBKDF2-HMAC-SHA256 (600,000 iterations). Older backups use key = SHA-256(password)
// with the 12-byte nonce in front of the ciphertext. Both are still in use.
var pbkdf2Magic = []byte{'V', 'L', 'T', 0x02}

const (
	pbkdf2SaltLen    = 16
	pbkdf2IVLen      = 12
	pbkdf2Iterations = 600_000
	pbkdf2HeaderLen  = 4 + pbkdf2SaltLen + pbkdf2IVLen
)

func isPbkdf2Backup(data []byte) bool {
	return bytes.HasPrefix(data, pbkdf2Magic)
}

func decryptPbkdf2(password string, data []byte) ([]byte, error) {
	if len(data) < pbkdf2HeaderLen+16 {
		return nil, fmt.Errorf("encrypted data too short")
	}
	salt := data[4 : 4+pbkdf2SaltLen]
	iv := data[4+pbkdf2SaltLen : pbkdf2HeaderLen]

	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm.Open(nil, iv, data[pbkdf2HeaderLen:], nil)
}

func DecryptWithPassword(encryptedData []byte, password string) ([]byte, error) {
	vaultData, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault data: %w", err)
	}

	if isPbkdf2Backup(vaultData) {
		plaintext, err := decryptPbkdf2(password, vaultData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
		return plaintext, nil
	}

	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(vaultData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := vaultData[:nonceSize], vaultData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func decryptVaultHelper(password string, vault []byte) ([]byte, error) {
	if isPbkdf2Backup(vault) {
		return decryptPbkdf2(password, vault)
	}

	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(vault) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func decryptVault(vaultContainer *v1.VaultContainer, fileName string, password string, source InputSource) (*v1.Vault, error) {
	vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault: %w", err)
	}

	if vaultContainer.IsEncrypted && source == CommandLine {
		if password == "" {
			fmt.Printf("Enter password to decrypt the vault (%s): ", fileName)
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %w", err)
			}
			password = string(bytePassword)
			fmt.Println()
		}
	}

	decryptedVaultData, err := decryptVaultHelper(password, vaultData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting file %s: %w", fileName, err)
	}

	var v v1.Vault
	err = proto.Unmarshal(decryptedVaultData, &v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	return &v, nil
}
