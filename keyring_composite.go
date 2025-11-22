//go:build (dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd

package keyring

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
