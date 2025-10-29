//go:build (dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd

package keyring

import (
	"fmt"

	dbus "github.com/godbus/dbus/v5"
	ss "github.com/zalando/go-keyring/secret_service"
)

type compositeProvider struct {
	primary  Keyring
	fallback Keyring
}

func (c compositeProvider) Set(service, user, pass string) error {
	err := c.primary.Set(service, user, pass)
	if err != nil && c.fallback != nil {
		return c.fallback.Set(service, user, pass)
	}
	return err
}

func (c compositeProvider) Get(service, user string) (string, error) {
	result, err := c.primary.Get(service, user)
	if err != nil && c.fallback != nil {
		return c.fallback.Get(service, user)
	}
	return result, err
}

func (c compositeProvider) Delete(service, user string) error {
	err := c.primary.Delete(service, user)
	if err != nil && c.fallback != nil {
		return c.fallback.Delete(service, user)
	}
	return err
}

func (c compositeProvider) DeleteAll(service string) error {
	err := c.primary.DeleteAll(service)
	if err != nil && c.fallback != nil {
		return c.fallback.DeleteAll(service)
	}
	return err
}

type secretServiceProvider struct{}

func (s secretServiceProvider) Set(service, user, pass string) error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	session, err := svc.OpenSession()
	if err != nil {
		return err
	}
	defer svc.Close(session)

	attributes := map[string]string{
		"username": user,
		"service":  service,
	}

	secret := ss.NewSecret(session.Path(), pass)

	collection := svc.GetLoginCollection()

	err = svc.Unlock(collection.Path())
	if err != nil {
		return err
	}

	err = svc.CreateItem(collection,
		fmt.Sprintf("Password for '%s' on '%s'", user, service),
		attributes, secret)
	if err != nil {
		return err
	}

	return nil
}

func (s secretServiceProvider) findItem(svc *ss.SecretService, service, user string) (dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"username": user,
		"service":  service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return "", err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "", ErrNotFound
	}

	return results[0], nil
}

func (s secretServiceProvider) findServiceItems(svc *ss.SecretService, service string) ([]dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"service": service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	if len(results) == 0 {
		return []dbus.ObjectPath{}, ErrNotFound
	}

	return results, nil
}

func (s secretServiceProvider) Get(service, user string) (string, error) {
	svc, err := ss.NewSecretService()
	if err != nil {
		return "", err
	}

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return "", err
	}

	session, err := svc.OpenSession()
	if err != nil {
		return "", err
	}
	defer svc.Close(session)

	err = svc.Unlock(item)
	if err != nil {
		return "", err
	}

	secret, err := svc.GetSecret(item, session.Path())
	if err != nil {
		return "", err
	}

	return string(secret.Value), nil
}

func (s secretServiceProvider) Delete(service, user string) error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return err
	}

	return svc.Delete(item)
}

func (s secretServiceProvider) DeleteAll(service string) error {
	if service == "" {
		return ErrNotFound
	}

	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	items, err := s.findServiceItems(svc, service)
	if err != nil {
		if err == ErrNotFound {
			return nil
		}
		return err
	}
	for _, item := range items {
		err = svc.Delete(item)
		if err != nil {
			return err
		}
	}
	return nil
}

var getFallbackProvider = func() Keyring {
	return nil
}

func init() {
	svc, err := ss.NewSecretService()
	if err == nil {
		svc.Close(nil)
		provider = secretServiceProvider{}
	} else {
		fallback := getFallbackProvider()
		if fallback != nil {
			provider = compositeProvider{
				primary:  secretServiceProvider{},
				fallback: fallback,
			}
		} else {
			provider = secretServiceProvider{}
		}
	}
}
