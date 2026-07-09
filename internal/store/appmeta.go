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
	// Reconstruct from the ESCAPED path, not u.Path (which is percent-decoded):
	// decoding would silently turn an encoded reserved char in the path (e.g.
	// %23 -> '#', %3F -> '?') into a delimiter, corrupting the stored URL and
	// breaking icon_url = base_url + icon downstream.
	path := strings.TrimRight(u.EscapedPath(), "/")
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
	// Validate the raw string AND its percent-decoded form: a browser normalizes
	// encoded traversal (%2E%2E) and encoded delimiters (%2F, %3A) during path
	// resolution, so a substring check on the raw bytes alone is bypassable.
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return errors.New("icon path is not a valid path")
	}
	for _, s := range []string{raw, decoded} {
		if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
			return errors.New("icon must be a rooted path under base_url starting with a single '/'")
		}
		if strings.Contains(s, "://") {
			return errors.New("icon must be a relative path under base_url, not an absolute URL")
		}
		if strings.Contains(s, "..") {
			return errors.New("icon path must not contain '..'")
		}
	}
	return nil
}
