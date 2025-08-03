package account

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// Compile regex once for better performance
var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// Domain errors
var (
	ErrUsernameTooShort     = errors.New("username must be at least 3 characters")
	ErrUsernameTooLong      = errors.New("username cannot exceed 30 characters")
	ErrUsernameInvalidChars = errors.New("username can only contain letters, numbers, and underscore")
	ErrInvalidEmail         = errors.New("invalid email format")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters")
	ErrPasswordTooWeak      = errors.New("password must contain uppercase, lowercase, number, and special character")
)

// Username value object
type Username struct {
	value string
}

func NewUsername(value string) (*Username, error) {
	value = strings.TrimSpace(value)
	
	if len(value) < 3 {
		return nil, ErrUsernameTooShort
	}
	
	if len(value) > 30 {
		return nil, ErrUsernameTooLong
	}
	
	if !usernameRegex.MatchString(value) {
		return nil, ErrUsernameInvalidChars
	}
	
	return &Username{value: value}, nil
}

func (u Username) String() string {
	return u.value
}

func (u Username) Value() string {
	return u.value
}

func (u Username) Equals(other Username) bool {
	return u.value == other.value
}

// Email value object
type Email struct {
	value string
}

func NewEmail(value string) (*Email, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	
	if !emailRegex.MatchString(value) {
		return nil, ErrInvalidEmail
	}
	
	return &Email{value: value}, nil
}

func (e Email) String() string {
	return e.value
}

func (e Email) Value() string {
	return e.value
}

func (e Email) Equals(other Email) bool {
	return e.value == other.value
}

// Domain interface for password hashing (implementation will be in infrastructure layer)
type PasswordHasher interface {
	Hash(raw string) (string, error)
	Compare(raw, encoded string) (bool, error)
}

// PasswordHash value object
type PasswordHash struct {
	value string
}

func NewPasswordHash(value string) PasswordHash {
	return PasswordHash{value: value}
}

func (h PasswordHash) Value() string {
	return h.value
}

func (h PasswordHash) Equals(other PasswordHash) bool {
	return h.value == other.value
}

// Method to compare password using the provided hasher
func (h PasswordHash) Compare(raw string, hasher PasswordHasher) (bool, error) {
	return hasher.Compare(raw, h.value)
}

// Password validation function (domain rule)
func ValidatePassword(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return ErrInvalidPassword
	}

	if len(raw) < 8 {
		return ErrPasswordTooShort
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, r := range raw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return ErrPasswordTooWeak
	}

	return nil
}

// Helper functions for password strength checking
func HasMinLength(password string, minLength int) bool {
	return len(password) >= minLength
}

func HasUppercase(password string) bool {
	for _, r := range password {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func HasLowercase(password string) bool {
	for _, r := range password {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func HasNumber(password string) bool {
	for _, r := range password {
		if unicode.IsNumber(r) {
			return true
		}
	}
	return false
}

func HasSpecialChar(password string) bool {
	for _, r := range password {
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}
