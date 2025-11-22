//go:build linux

package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
	tokenPath, err := getTokenFilePath(service)
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

	tokens[user] = password

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
	tokenPath, err := getTokenFilePath(service)
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

	token, ok := tokens[user]
	if !ok {
		return "", ErrNotFound
	}

	return token, nil
}

func (f *fileProvider) Delete(service, user string) error {
	tokenPath, err := getTokenFilePath(service)
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

	if _, ok := tokens[user]; !ok {
		return ErrNotFound
	}

	delete(tokens, user)

	if len(tokens) == 0 {
		if err := os.Remove(tokenPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove token file: %w", err)
		}
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

func (f *fileProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	tokenPath, err := getTokenFilePath(service)
	if err != nil {
		return err
	}

	if err := os.Remove(tokenPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to remove token file: %w", err)
	}

	return nil
}

func getTokenFilePath(service string) (string, error) {
	configDirPath, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	filename := fmt.Sprintf("%s.json", service)
	tokenPath := filepath.Join(configDirPath, "go-keyring", filename)
	return tokenPath, nil
}

