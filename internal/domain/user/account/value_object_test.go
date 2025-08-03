package account

import (
	"testing"
)

// Username Tests
func TestNewUsername(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    string
		expectError bool
		expectedErr error
	}{
		{"valid username", "joko_saputro95", "joko_saputro95", false, nil},
		{"valid username with numbers", "user123", "user123", false, nil},
		{"valid username with underscore", "test_user_account", "test_user_account", false, nil},
		{"valid minimum length", "abc", "abc", false, nil},
		{"valid maximum length", "user12345678901234567890123456", "user12345678901234567890123456", false, nil},
		{"invalid - too short", "jo", "", true, ErrUsernameTooShort},
		{"invalid - too long", "jokosaputro95jokosaputro95jokosaputro95", "", true, ErrUsernameTooLong},
		{"invalid - contains space", "wrong username", "", true, ErrUsernameInvalidChars},
		{"invalid - contains special char", "user!", "", true, ErrUsernameInvalidChars},
		{"invalid - contains dash", "user-name", "", true, ErrUsernameInvalidChars},
		{"invalid - empty string", "", "", true, ErrUsernameTooShort},
		{"invalid - only spaces", "   ", "", true, ErrUsernameTooShort},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := NewUsername(tc.input)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected an error, but got none")
					return
				}
				if tc.expectedErr != nil && err != tc.expectedErr {
					t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u.String() != tc.expected {
				t.Errorf("expected username '%s', got '%s'", tc.expected, u.String())
			}
			if u.Value() != tc.expected {
				t.Errorf("expected username value '%s', got '%s'", tc.expected, u.Value())
			}
		})
	}
}

func TestUsername_Equals(t *testing.T) {
	u1, _ := NewUsername("testuser")
	u2, _ := NewUsername("testuser")
	u3, _ := NewUsername("otheruser")

	if !u1.Equals(*u2) {
		t.Error("expected equal usernames to return true")
	}
	if u1.Equals(*u3) {
		t.Error("expected different usernames to return false")
	}
}

// Email Tests
func TestNewEmail(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    string
		expectError bool
		expectedErr error
	}{
		{"valid email", "user@example.com", "user@example.com", false, nil},
		{"valid email with subdomain", "user@mail.example.com", "user@mail.example.com", false, nil},
		{"valid email with plus", "user+tag@example.com", "user+tag@example.com", false, nil},
		{"valid email with dot", "first.last@domain.co", "first.last@domain.co", false, nil},
		{"valid email with numbers", "user123@example.com", "user123@example.com", false, nil},
		{"case insensitive", "USER@EXAMPLE.COM", "user@example.com", false, nil},
		{"trim spaces", "  user@example.com  ", "user@example.com", false, nil},
		{"invalid - missing @", "userexample.com", "", true, ErrInvalidEmail},
		{"invalid - missing domain", "user@", "", true, ErrInvalidEmail},
		{"invalid - missing local part", "@example.com", "", true, ErrInvalidEmail},
		{"invalid - missing TLD", "user@example", "", true, ErrInvalidEmail},
		{"invalid - invalid TLD", "user@example.c", "", true, ErrInvalidEmail},
		{"invalid - empty string", "", "", true, ErrInvalidEmail},
		{"invalid - only spaces", "   ", "", true, ErrInvalidEmail},
		{"invalid - multiple @", "user@@example.com", "", true, ErrInvalidEmail},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewEmail(tc.input)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
					return
				}
				if tc.expectedErr != nil && err != tc.expectedErr {
					t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.String() != tc.expected {
				t.Errorf("expected email '%s', got '%s'", tc.expected, e.String())
			}
			if e.Value() != tc.expected {
				t.Errorf("expected email value '%s', got '%s'", tc.expected, e.Value())
			}
		})
	}
}

func TestEmail_Equals(t *testing.T) {
	e1, _ := NewEmail("test@example.com")
	e2, _ := NewEmail("test@example.com")
	e3, _ := NewEmail("other@example.com")

	if !e1.Equals(*e2) {
		t.Error("expected equal emails to return true")
	}
	if e1.Equals(*e3) {
		t.Error("expected different emails to return false")
	}
}

// Password Validation Tests
func TestValidatePassword(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
		expectedErr error
	}{
		{"valid - all requirements", "Password1!", false, nil},
		{"valid - with symbols", "MyP@ssw0rd", false, nil},
		{"valid - with different special chars", "Pass1#$%", false, nil},
		{"valid - minimum valid password", "Aa1!test!", false, nil},
		{"invalid - too short", "P1!", true, ErrPasswordTooShort},
		{"invalid - no uppercase", "password1!", true, ErrPasswordTooWeak},
		{"invalid - no lowercase", "PASSWORD1!", true, ErrPasswordTooWeak},
		{"invalid - no number", "Password!", true, ErrPasswordTooWeak},
		{"invalid - no special char", "Password1", true, ErrPasswordTooWeak},
		{"invalid - empty", "", true, ErrInvalidPassword},
		{"invalid - only spaces", "   ", true, ErrInvalidPassword},
		{"invalid - only uppercase", "ABCDEFGH", true, ErrPasswordTooWeak},
		{"invalid - only lowercase", "abcdefgh", true, ErrPasswordTooWeak},
		{"invalid - only numbers", "12345678", true, ErrPasswordTooWeak},
		{"invalid - only special chars", "!@#$%^&*", true, ErrPasswordTooWeak},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.input)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
					return
				}
				if tc.expectedErr != nil && err != tc.expectedErr {
					t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// PasswordHash Tests
func TestNewPasswordHash_Value_And_Equals(t *testing.T) {
	hashStr := "$2a$10$somerandomhashvalue"
	ph := NewPasswordHash(hashStr)

	if ph.Value() != hashStr {
		t.Errorf("expected value '%s', got '%s'", hashStr, ph.Value())
	}

	ph2 := NewPasswordHash(hashStr)
	if !ph.Equals(ph2) {
		t.Error("expected PasswordHash.Equals to return true for same value")
	}

	ph3 := NewPasswordHash("$2a$10$anotherhashvalue")
	if ph.Equals(ph3) {
		t.Error("expected PasswordHash.Equals to return false for different value")
	}
}

// Helper function tests
func TestPasswordHelperFunctions(t *testing.T) {
	t.Run("HasMinLength", func(t *testing.T) {
		if !HasMinLength("password", 8) {
			t.Error("expected HasMinLength to return true for valid length")
		}
		if HasMinLength("short", 8) {
			t.Error("expected HasMinLength to return false for short password")
		}
	})

	t.Run("HasUppercase", func(t *testing.T) {
		if !HasUppercase("Password") {
			t.Error("expected HasUppercase to return true")
		}
		if HasUppercase("password") {
			t.Error("expected HasUppercase to return false")
		}
	})

	t.Run("HasLowercase", func(t *testing.T) {
		if !HasLowercase("Password") {
			t.Error("expected HasLowercase to return true")
		}
		if HasLowercase("PASSWORD") {
			t.Error("expected HasLowercase to return false")
		}
	})

	t.Run("HasNumber", func(t *testing.T) {
		if !HasNumber("Password1") {
			t.Error("expected HasNumber to return true")
		}
		if HasNumber("Password") {
			t.Error("expected HasNumber to return false")
		}
	})

	t.Run("HasSpecialChar", func(t *testing.T) {
		if !HasSpecialChar("Password!") {
			t.Error("expected HasSpecialChar to return true")
		}
		if HasSpecialChar("Password1") {
			t.Error("expected HasSpecialChar to return false")
		}
	})
}

// Mock hasher for testing password comparison
type MockPasswordHasher struct{}

func (m *MockPasswordHasher) Hash(raw string) (string, error) {
	return "hashed_" + raw, nil
}

func (m *MockPasswordHasher) Compare(raw, encoded string) (bool, error) {
	expected := "hashed_" + raw
	return expected == encoded, nil
}

func TestPasswordHash_Compare(t *testing.T) {
	hasher := &MockPasswordHasher{}
	
	// Test successful comparison
	hash := NewPasswordHash("hashed_password123")
	match, err := hash.Compare("password123", hasher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected password to match")
	}

	// Test failed comparison
	match, err = hash.Compare("wrongpassword", hasher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected password to not match")
	}
}