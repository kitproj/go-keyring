//go:build linux

package keyring

import (
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
	tokenPath, err := getTokenFilePath(service, user)
	if err != nil {
		return err
	}

	configDirPath := filepath.Dir(tokenPath)
	if err := os.MkdirAll(configDirPath, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(tokenPath, []byte(password), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

func (f *fileProvider) Get(service, user string) (string, error) {
	tokenPath, err := getTokenFilePath(service, user)
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

	return string(data), nil
}

func (f *fileProvider) Delete(service, user string) error {
	tokenPath, err := getTokenFilePath(service, user)
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

func (f *fileProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	configDirPath, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	serviceDir := filepath.Join(configDirPath, "go-keyring", service)

	entries, err := os.ReadDir(serviceDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read service directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			filePath := filepath.Join(serviceDir, entry.Name())
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove token file: %w", err)
			}
		}
	}

	if err := os.Remove(serviceDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service directory: %w", err)
	}

	return nil
}

func getTokenFilePath(service, user string) (string, error) {
	configDirPath, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	return filepath.Join(configDirPath, "go-keyring", service, user), nil
}
