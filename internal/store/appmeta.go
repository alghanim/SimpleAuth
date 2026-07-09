package store

import (
	"errors"
	"net/url"
	"strings"
)

// NormalizeBaseURL validates a module's canonical origin (SA-1) and returns it
// normalized. It is stored and returned but NEVER dereferenced by SimpleAuth, so
// validation is purely syntactic: an absolute https URL with a host, an optional
// path prefix, and no userinfo/query/fragment; the trailing slash is stripped.
// Empty is allowed (a non-launchable app). Deliberately strict so a stored
// base_url can be trusted as a same-origin launch target without runtime checks
// — enforced on EVERY write path (admin API and migration import).
func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("base_url is not a valid URL")
	}
	if u.Scheme != "https" {
		return "", errors.New("base_url must be an absolute https:// URL")
	}
	if u.Host == "" {
		return "", errors.New("base_url must include a host")
	}
	if u.User != nil {
		return "", errors.New("base_url must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("base_url must not contain a query or fragment")
	}
	path := strings.TrimRight(u.Path, "/")
	return u.Scheme + "://" + u.Host + path, nil
}

// ValidateIconPath ensures the icon is a rooted relative path under base_url,
// never an absolute/remote URL or a traversal. Because SA-2 serves
// icon_url = base_url + icon by concatenation, requiring a single leading '/'
// (and forbidding '//', '://' and '..') keeps the result on base_url's origin.
// Empty is allowed.
func ValidateIconPath(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return errors.New("icon must be a rooted path under base_url starting with a single '/'")
	}
	if strings.Contains(raw, "://") {
		return errors.New("icon must be a relative path under base_url, not an absolute URL")
	}
	if strings.Contains(raw, "..") {
		return errors.New("icon path must not contain '..'")
	}
	return nil
}
