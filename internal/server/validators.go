package server

import "github.com/google/uuid"

// IsUUIDv4 returns true if s is a valid UUID version 4 string (RFC 4122 variant).
func IsUUIDv4(s string) bool {
	u, err := uuid.Parse(s)
	if err != nil {
		return false
	}
	return u.Version() == 4 && u.Variant() == uuid.RFC4122
}
