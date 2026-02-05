package server

import "testing"

func TestIsUUIDv4(t *testing.T) {
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"7c2f3f7a-6b4e-4f3f-8b2a-1a9b3c2d4e5f",
		"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
		"550e8400e29b41d4a716446655440000", // no dashes (RFC allows)
	}
	for _, s := range valid {
		if !IsUUIDv4(s) {
			t.Errorf("IsUUIDv4(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"550e8400-e29b-41d4-a716-44665544000",   // too short
		"550e8400-e29b-41d4-a716-4466554400000", // too long
		"550e8400-e29b-41d4-a716-44665544000g",  // invalid hex
		"550e8400-e29b-11d4-a716-446655440000",  // version 1
		"550e8400-e29b-31d4-a716-446655440000",  // version 3
		"550e8400-e29b-51d4-a716-446655440000",  // version 5
		"550e8400-e29b-41d4-0716-446655440000",  // variant 0 (invalid)
	}
	for _, s := range invalid {
		if IsUUIDv4(s) {
			t.Errorf("IsUUIDv4(%q) = true, want false", s)
		}
	}
}
