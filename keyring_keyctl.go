//go:build linux

package keyring

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

type keyctlProvider struct{}

func init() {
	fileFallback := &fileProvider{}
	getFallbackProvider = func() Keyring {
		return compositeProvider{
			primary:  keyctlProvider{},
			fallback: fileFallback,
		}
	}
}

// getPersistentKeyring gets or creates the persistent keyring for the current user.
func (k keyctlProvider) getPersistentKeyring() (int, error) {
	persistentKeyringID, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, -1, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get persistent keyring: %w", err)
	}
	return persistentKeyringID, nil
}

func (k keyctlProvider) Set(service, user, pass string) error {
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	existingKeyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyName, 0)
	if err == nil {
		_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, existingKeyID, persistentKeyring, 0, 0)
	}

	_, err = unix.AddKey("user", keyName, []byte(pass), persistentKeyring)
	return err
}

func (k keyctlProvider) Get(service, user string) (string, error) {
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return "", err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	keyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyName, 0)
	if err != nil {
		return "", ErrNotFound
	}

	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, nil, 0)
	if err != nil {
		return "", err
	}

	buf := make([]byte, size)
	_, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

func (k keyctlProvider) Delete(service, user string) error {
	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s:%s", service, user)

	keyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyName, 0)
	if err != nil {
		return ErrNotFound
	}

	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, persistentKeyring, 0, 0)
	return err
}

// DeleteAll deletes all secrets for a given service.
func (k keyctlProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	persistentKeyring, err := k.getPersistentKeyring()
	if err != nil {
		return err
	}

	cmd := exec.Command("keyctl", "show", fmt.Sprintf("%d", persistentKeyring))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(output), "\n")
	prefix := fmt.Sprintf("%s:", service)

	for _, line := range lines {
		if !strings.Contains(line, prefix) {
			continue
		}

		parts := strings.Split(line, "user:")
		if len(parts) < 2 {
			continue
		}

		keyDesc := strings.TrimSpace(parts[1])
		if !strings.HasPrefix(keyDesc, service+":") {
			continue
		}

		keyID, err := unix.KeyctlSearch(persistentKeyring, "user", keyDesc, 0)
		if err == nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, persistentKeyring, 0, 0)
		}
	}

	return nil
}
