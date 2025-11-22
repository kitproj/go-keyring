//go:build linux

package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const tokenFile = "tokens.json"

type fileProvider struct{}

func init() {
	originalFallback := getFallbackProvider
	getFallbackProvider = func() Keyring {
		fallback := originalFallback()
		if fallback != nil {
			return fallback
		}
		return &fileProvider{}
	}
}

func (f *fileProvider) Set(service, user, password string) error {
	tokenPath, err := getTokenFilePath()
	if err != nil {
		return err
	}

	configDirPath := filepath.Dir(tokenPath)
	if err := os.MkdirAll(configDirPath, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	tokens := make(map[string]string)

	if data, err := os.ReadFile(tokenPath); err == nil {
		_ = json.Unmarshal(data, &tokens)
	}

	key := fmt.Sprintf("%s:%s", service, user)
	tokens[key] = password

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

func (f *fileProvider) Get(service, user string) (string, error) {
	tokenPath, err := getTokenFilePath()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("failed to read token file: %w", err)
	}

	tokens := make(map[string]string)
	if err := json.Unmarshal(data, &tokens); err != nil {
		return "", fmt.Errorf("failed to parse token file: %w", err)
	}

	key := fmt.Sprintf("%s:%s", service, user)
	token, ok := tokens[key]
	if !ok {
		return "", ErrNotFound
	}

	return token, nil
}

func (f *fileProvider) Delete(service, user string) error {
	tokenPath, err := getTokenFilePath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("failed to read token file: %w", err)
	}

	tokens := make(map[string]string)
	if err := json.Unmarshal(data, &tokens); err != nil {
		return fmt.Errorf("failed to parse token file: %w", err)
	}

	key := fmt.Sprintf("%s:%s", service, user)
	if _, ok := tokens[key]; !ok {
		return ErrNotFound
	}

	delete(tokens, key)

	data, err = json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

func (f *fileProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	tokenPath, err := getTokenFilePath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read token file: %w", err)
	}

	tokens := make(map[string]string)
	if err := json.Unmarshal(data, &tokens); err != nil {
		return fmt.Errorf("failed to parse token file: %w", err)
	}

	prefix := service + ":"
	found := false
	for key := range tokens {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			delete(tokens, key)
			found = true
		}
	}

	if !found {
		return nil
	}

	data, err = json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

func getTokenFilePath() (string, error) {
	configDirPath, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	tokenPath := filepath.Join(configDirPath, "go-keyring", tokenFile)
	return tokenPath, nil
}

