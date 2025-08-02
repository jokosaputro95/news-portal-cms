package account

import (
	"testing"
)

// Username Test
func TestNewUsername(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{"valid username", "joko_saputro95", "joko_saputro95", false},
		{"valid username with numbers", "user123", "user123", false},
		{"valid username with underscore", "test_user_account", "test_user_account", false},
		{"invalid - too short", "jo", "", true},
		{"invalid - too long", "jokosaputro95jokosaputro95jokosaputro95jokosaputro95jokosaputro95", "", true},
		{"invalid - contains space", "wrong username", "", true},
		{"invalid - contains special char", "user!", "", true},
		{"invalid - empty string", "", "", true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := NewUsername(tc.input)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected an error, but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u.String() != tc.expected {
				t.Errorf("expected username '%s', got '%s'", tc.expected, u.String())
			}
		})
	}
}

// Email Test
func TestNewEmail(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{"valid email", "user@example.com", "user@example.com", false},
		{"valid email with dot", "first.last@domain.co", "first.last@domain.co", false},
		{"invalid - missing @", "userexample.com", "", true},
		{"invalid - missing domain", "user@", "", true},
		{"invalid - empty string", "", "", true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewEmail(tc.input)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.String() != tc.expected {
				t.Errorf("expected email '%s', got '%s'", tc.expected, e.String())
			}
		})
	}
}

// Password Test
func TestValidatePassword(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"valid - all requirements", "Password1!", false},
		{"invalid - too short", "P1!", true},
		{"invalid - no uppercase", "password1!", true},
		{"invalid - no lowercase", "PASSWORD1!", true},
		{"invalid - no number", "Password!", true},
		{"invalid - no special", "Password1", true},
		{"invalid - empty", "", true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.input)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// PasswordHash Test
func TestNewPasswordHash_Value_And_Equals(t *testing.T) {
	hashStr := "somerandomhash"
	ph := NewPasswordHash(hashStr)

	if ph.Value() != hashStr {
		t.Errorf("expected value '%s', got '%s'", hashStr, ph.Value())
	}

	ph2 := NewPasswordHash(hashStr)
	if !ph.Equals(ph2) {
		t.Error("expected PasswordHash.Equals to return true for same value")
	}

	ph3 := NewPasswordHash("anotherhash")
	if ph.Equals(ph3) {
		t.Error("expected PasswordHash.Equals to return false for different value")
	}
}
