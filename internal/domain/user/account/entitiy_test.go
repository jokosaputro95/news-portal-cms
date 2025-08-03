package account

import (
	"testing"
	"time"
)

func TestNewUserAccountWithHash(t *testing.T) {
	tests := []struct {
		name           string
		id             string
		username       string
		email          string
		hashedPassword string
		accountType    UserAccountType
		registeredBy   string
		wantErr        bool
		errMsg         string
	}{
		// Test all account types
		{
			name:           "valid internal account",
			id:             "123",
			username:       "johndoe",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        false,
		},
		{
			name:           "valid external account",
			id:             "124",
			username:       "contributor1",
			email:          "contributor@example.com",
			hashedPassword: "hashed_password_124",
			accountType:    TypeExternal,
			registeredBy:   "admin123",
			wantErr:        false,
		},
		{
			name:           "valid membership account (self-registered)",
			id:             "125",
			username:       "member1",
			email:          "member@example.com",
			hashedPassword: "hashed_password_125",
			accountType:    TypeMembership,
			registeredBy:   SelfRegistration,
			wantErr:        false,
		},
		{
			name:           "valid partner account",
			id:             "126",
			username:       "partner1",
			email:          "partner@company.com",
			hashedPassword: "hashed_password_126",
			accountType:    TypePartner,
			registeredBy:   "admin123",
			wantErr:        false,
		},
		{
			name:           "valid developer account",
			id:             "127",
			username:       "dev1",
			email:          "dev@techco.com",
			hashedPassword: "hashed_password_127",
			accountType:    TypeDeveloper,
			registeredBy:   "system",
			wantErr:        false,
		},
		// Error cases
		{
			name:           "empty id",
			id:             "",
			username:       "johndoe",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "ID cannot be empty",
		},
		{
			name:           "invalid username - too short",
			id:             "123",
			username:       "jo",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "username must be at least 3 characters",
		},
		{
			name:           "invalid username - too long",
			id:             "123",
			username:       "this_username_is_way_too_long_for_our_system",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "username cannot exceed 30 characters",
		},
		{
			name:           "invalid username - special chars",
			id:             "123",
			username:       "john@doe",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "username can only contain letters, numbers, and underscore",
		},
		{
			name:           "invalid email",
			id:             "123",
			username:       "johndoe",
			email:          "invalid-email",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "invalid email format",
		},
		{
			name:           "empty password hash",
			id:             "123",
			username:       "johndoe",
			email:          "john@example.com",
			hashedPassword: "",
			accountType:    TypeInternal,
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "password hash cannot be empty",
		},
		{
			name:           "invalid account type",
			id:             "123",
			username:       "johndoe",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    "invalid_type",
			registeredBy:   "admin123",
			wantErr:        true,
			errMsg:         "invalid account type",
		},
		{
			name:           "empty registeredBy",
			id:             "123",
			username:       "johndoe",
			email:          "john@example.com",
			hashedPassword: "hashed_password_123",
			accountType:    TypeInternal,
			registeredBy:   "",
			wantErr:        true,
			errMsg:         "registeredBy cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, err := NewUserAccountWithHash(tt.id, tt.username, tt.email, tt.hashedPassword, tt.accountType, tt.registeredBy)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if account == nil {
					t.Fatal("expected account to be created")
				}
				if account.ID != tt.id {
					t.Errorf("expected ID %s, got %s", tt.id, account.ID)
				}
				if account.Status != StatusPendingVerification {
					t.Errorf("expected status %s, got %s", StatusPendingVerification, account.Status)
				}
				if account.IsVerified {
					t.Error("expected account to be unverified")
				}
				if account.Type != tt.accountType {
					t.Errorf("expected account type %s, got %s", tt.accountType, account.Type)
				}
				if *account.RegisteredBy != tt.registeredBy {
					t.Errorf("expected registeredBy %s, got %s", tt.registeredBy, *account.RegisteredBy)
				}
			}
		})
	}
}

func TestNewUserAccountForTesting(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		username     string
		email        string
		password     string
		accountType  UserAccountType
		registeredBy string
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "valid password",
			id:           "123",
			username:     "testuser",
			email:        "test@example.com",
			password:     "ValidPass123!",
			accountType:  TypeInternal,
			registeredBy: "admin123",
			wantErr:      false,
		},
		{
			name:         "password too short",
			id:           "123",
			username:     "testuser",
			email:        "test@example.com",
			password:     "Pass1!",
			accountType:  TypeInternal,
			registeredBy: "admin123",
			wantErr:      true,
			errMsg:       "password must be at least 8 characters",
		},
		{
			name:         "password missing uppercase",
			id:           "123",
			username:     "testuser",
			email:        "test@example.com",
			password:     "validpass123!",
			accountType:  TypeInternal,
			registeredBy: "admin123",
			wantErr:      true,
			errMsg:       "password must contain uppercase, lowercase, number, and special character",
		},
		{
			name:         "password missing lowercase",
			id:           "123",
			username:     "testuser",
			email:        "test@example.com",
			password:     "VALIDPASS123!",
			accountType:  TypeInternal,
			registeredBy: "admin123",
			wantErr:      true,
			errMsg:       "password must contain uppercase, lowercase, number, and special character",
		},
		{
			name:         "password missing number",
			id:           "123",
			username:     "testuser",
			email:        "test@example.com",
			password:     "ValidPass!",
			accountType:  TypeInternal,
			registeredBy: "admin123",
			wantErr:      true,
			errMsg:       "password must contain uppercase, lowercase, number, and special character",
		},
		{
			name:         "password missing special char",
			id:           "123",
			username:     "testuser",
			email:        "test@example.com",
			password:     "ValidPass123",
			accountType:  TypeInternal,
			registeredBy: "admin123",
			wantErr:      true,
			errMsg:       "password must contain uppercase, lowercase, number, and special character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, err := NewUserAccountForTesting(tt.id, tt.username, tt.email, tt.password, tt.accountType, tt.registeredBy)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if account == nil {
					t.Fatal("expected account to be created")
				}
				// Verify password hash format for testing
				expectedHash := "hashed_" + tt.password
				if account.PasswordHash.Value() != expectedHash {
					t.Errorf("expected password hash %s, got %s", expectedHash, account.PasswordHash.Value())
				}
			}
		})
	}
}

func TestNewUserAccountForSelfRegistration(t *testing.T) {
	account, err := NewUserAccountForSelfRegistration(
		"member123",
		"member_user",
		"member@example.com",
		"hashed_password",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if account.Type != TypeMembership {
		t.Errorf("expected account type %s, got %s", TypeMembership, account.Type)
	}

	if *account.RegisteredBy != SelfRegistration {
		t.Errorf("expected registeredBy %s, got %s", SelfRegistration, *account.RegisteredBy)
	}

	if !account.IsSelfRegistered() {
		t.Error("expected account to be self-registered")
	}
}

func TestUserAccount_Verify(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*UserAccount)
		verifierID string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "successful verification",
			setup:      func(ua *UserAccount) {},
			verifierID: "admin123",
			wantErr:    false,
		},
		{
			name: "already active account",
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
			},
			verifierID: "admin123",
			wantErr:    true,
			errMsg:     "user account is not pending verification",
		},
		{
			name: "already verified account",
			setup: func(ua *UserAccount) {
				ua.IsVerified = true
			},
			verifierID: "admin123",
			wantErr:    true,
			errMsg:     "user account is already verified",
		},
		{
			name:       "empty verifier ID",
			setup:      func(ua *UserAccount) {},
			verifierID: "",
			wantErr:    true,
			errMsg:     "verifier ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAccount := createTestAccount(t, TypeInternal)
			tt.setup(testAccount)
			
			err := testAccount.Verify(tt.verifierID)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if testAccount.Status != StatusActive {
					t.Errorf("expected status %s, got %s", StatusActive, testAccount.Status)
				}
				if !testAccount.IsVerified {
					t.Error("expected account to be verified")
				}
				if testAccount.VerifiedBy == nil || *testAccount.VerifiedBy != tt.verifierID {
					t.Error("expected verifiedBy to be set")
				}
				if testAccount.VerifiedAt == nil {
					t.Error("expected verifiedAt to be set")
				}
			}
		})
	}
}

func TestUserAccount_SelfVerify(t *testing.T) {
	tests := []struct {
		name        string
		accountType UserAccountType
		setup       func(*UserAccount)
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "successful self-verification for membership",
			accountType: TypeMembership,
			setup:       func(ua *UserAccount) {},
			wantErr:     false,
		},
		{
			name:        "self-verification not allowed for internal",
			accountType: TypeInternal,
			setup:       func(ua *UserAccount) {},
			wantErr:     true,
			errMsg:      "self-verification only allowed for membership accounts",
		},
		{
			name:        "self-verification not allowed for external",
			accountType: TypeExternal,
			setup:       func(ua *UserAccount) {},
			wantErr:     true,
			errMsg:      "self-verification only allowed for membership accounts",
		},
		{
			name:        "already verified",
			accountType: TypeMembership,
			setup: func(ua *UserAccount) {
				ua.IsVerified = true
			},
			wantErr: true,
			errMsg:  "user account is already verified",
		},
		{
			name:        "not pending verification",
			accountType: TypeMembership,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
			},
			wantErr: true,
			errMsg:  "user account is not pending verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAccount := createTestAccount(t, tt.accountType)
			tt.setup(testAccount)
			
			err := testAccount.SelfVerify()
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if testAccount.Status != StatusActive {
					t.Errorf("expected status %s, got %s", StatusActive, testAccount.Status)
				}
				if !testAccount.IsVerified {
					t.Error("expected account to be verified")
				}
				if testAccount.VerifiedBy == nil || *testAccount.VerifiedBy != SelfRegistration {
					t.Error("expected verifiedBy to be 'self'")
				}
			}
		})
	}
}

func TestUserAccount_Disable(t *testing.T) {
	tests := []struct {
		name           string
		accountType    UserAccountType
		setup          func(*UserAccount)
		disablerID     string
		disabilityType DisabilityType
		reason         string
		wantErr        bool
		errMsg         string
	}{
		{
			name:           "successful disable internal account",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
			},
			disablerID:     "admin123",
			disabilityType: DisabilityTypeSuspended,
			reason:         "violation of terms",
			wantErr:        false,
		},
		{
			name:           "successful disable external account",
			accountType:    TypeExternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
			},
			disablerID:     "admin123",
			disabilityType: DisabilityTypeViolation,
			reason:         "content plagiarism",
			wantErr:        false,
		},
		{
			name:           "successful disable membership account",
			accountType:    TypeMembership,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
			},
			disablerID:     "system",
			disabilityType: DisabilityTypeExpired,
			reason:         "subscription expired",
			wantErr:        false,
		},
		{
			name:           "disable deleted account",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusDeleted
			},
			disablerID:     "admin123",
			disabilityType: DisabilityTypeSuspended,
			reason:         "test",
			wantErr:        true,
			errMsg:         "cannot disable deleted account",
		},
		{
			name:           "disable unverified account",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusPendingVerification
			},
			disablerID:     "admin123",
			disabilityType: DisabilityTypeSuspended,
			reason:         "test",
			wantErr:        true,
			errMsg:         "cannot disable unverified account",
		},
		{
			name:           "already disabled with same type",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
				ua.Disable("admin", DisabilityTypeSuspended, "test")
			},
			disablerID:     "admin123",
			disabilityType: DisabilityTypeSuspended,
			reason:         "test again",
			wantErr:        true,
			errMsg:         "user account is already disabled with the same type",
		},
		{
			name:           "empty disabler ID",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
			},
			disablerID:     "",
			disabilityType: DisabilityTypeSuspended,
			reason:         "test",
			wantErr:        true,
			errMsg:         "disabler ID cannot be empty",
		},
		{
			name:           "empty reason",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
			},
			disablerID:     "admin123",
			disabilityType: DisabilityTypeSuspended,
			reason:         "",
			wantErr:        true,
			errMsg:         "reason cannot be empty",
		},
		{
			name:           "invalid disability type",
			accountType:    TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
			},
			disablerID:     "admin123",
			disabilityType: "invalid_type",
			reason:         "test",
			wantErr:        true,
			errMsg:         "invalid disability type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := createTestAccount(t, tt.accountType)
			tt.setup(account)
			
			err := account.Disable(tt.disablerID, tt.disabilityType, tt.reason)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if account.Status != StatusDisabled {
					t.Errorf("expected status %s, got %s", StatusDisabled, account.Status)
				}
				if account.DisabilityType == nil || *account.DisabilityType != tt.disabilityType {
					t.Error("expected disability type to be set")
				}
				if account.IssuedReason == nil || *account.IssuedReason != tt.reason {
					t.Error("expected reason to be set")
				}
			}
		})
	}
}

func TestUserAccount_Reactivate(t *testing.T) {
	tests := []struct {
		name          string
		accountType   UserAccountType
		setup         func(*UserAccount)
		reactivatorID string
		wantErr       bool
		errMsg        string
	}{
		{
			name:        "successful reactivation internal",
			accountType: TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
				ua.Disable("admin", DisabilityTypeSuspended, "test reason")
			},
			reactivatorID: "admin123",
			wantErr:       false,
		},
		{
			name:        "successful reactivation external",
			accountType: TypeExternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
				ua.Disable("admin", DisabilityTypeViolation, "content issue")
			},
			reactivatorID: "admin123",
			wantErr:       false,
		},
		{
			name:        "successful reactivation membership",
			accountType: TypeMembership,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
				ua.IsVerified = true
				ua.Disable("system", DisabilityTypeExpired, "subscription ended")
			},
			reactivatorID: "system",
			wantErr:       false,
		},
		{
			name:        "reactivate non-disabled account",
			accountType: TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusActive
			},
			reactivatorID: "admin123",
			wantErr:       true,
			errMsg:        "user account is not disabled, cannot be reactivated",
		},
		{
			name:        "empty reactivator ID",
			accountType: TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusDisabled
			},
			reactivatorID: "",
			wantErr:       true,
			errMsg:        "reactivator ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := createTestAccount(t, tt.accountType)
			tt.setup(account)
			
			err := account.Reactivate(tt.reactivatorID)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if account.Status != StatusActive {
					t.Errorf("expected status %s, got %s", StatusActive, account.Status)
				}
				if account.DisabilityType != nil {
					t.Error("expected disability type to be cleared")
				}
				if account.IssuedReason != nil {
					t.Error("expected reason to be cleared")
				}
			}
		})
	}
}

func TestUserAccount_Delete(t *testing.T) {
	tests := []struct {
		name        string
		accountType UserAccountType
		setup       func(*UserAccount)
		deleterID   string
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "successful deletion internal",
			accountType: TypeInternal,
			setup:       func(ua *UserAccount) {},
			deleterID:   "admin123",
			wantErr:     false,
		},
		{
			name:        "successful deletion external",
			accountType: TypeExternal,
			setup:       func(ua *UserAccount) {},
			deleterID:   "admin123",
			wantErr:     false,
		},
		{
			name:        "successful deletion membership",
			accountType: TypeMembership,
			setup:       func(ua *UserAccount) {},
			deleterID:   "system",
			wantErr:     false,
		},
		{
			name:        "already deleted",
			accountType: TypeInternal,
			setup: func(ua *UserAccount) {
				ua.Status = StatusDeleted
			},
			deleterID: "admin123",
			wantErr:   true,
			errMsg:    "user account is already deleted",
		},
		{
			name:        "empty deleter ID",
			accountType: TypeInternal,
			setup:       func(ua *UserAccount) {},
			deleterID:   "",
			wantErr:     true,
			errMsg:      "deleter ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := createTestAccount(t, tt.accountType)
			tt.setup(account)
			
			err := account.Delete(tt.deleterID)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if account.Status != StatusDeleted {
					t.Errorf("expected status %s, got %s", StatusDeleted, account.Status)
				}
				if account.DeletedAt == nil {
					t.Error("expected deletedAt to be set")
				}
				if account.DeletedBy == nil || *account.DeletedBy != tt.deleterID {
					t.Error("expected deletedBy to be set")
				}
			}
		})
	}
}

func TestUserAccount_LoginTracking(t *testing.T) {
	t.Run("successful login", func(t *testing.T) {
		account := createTestAccount(t, TypeMembership)
		account.Status = StatusActive
		account.IsVerified = true
		
		err := account.RecordSuccessfulLogin("192.168.1.1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		
		if account.LastLoginAt == nil {
			t.Error("expected lastLoginAt to be set")
		}
		if account.LastLoginIP == nil || *account.LastLoginIP != "192.168.1.1" {
			t.Error("expected lastLoginIP to be set")
		}
		if account.FailedLoginAttempts != 0 {
			t.Error("expected failed attempts to be reset")
		}
	})

	t.Run("failed login with lock", func(t *testing.T) {
		account := createTestAccount(t, TypeExternal)
		account.Status = StatusActive
		account.IsVerified = true
		
		// Record 3 failed attempts
		for i := 0; i < 3; i++ {
			err := account.RecordFailedLogin("192.168.1.1", 3, 30*time.Minute)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}
		
		if account.FailedLoginAttempts != 3 {
			t.Errorf("expected 3 failed attempts, got %d", account.FailedLoginAttempts)
		}
		if account.LockedUntil == nil {
			t.Error("expected account to be locked")
		}
		if !account.IsLocked() {
			t.Error("expected IsLocked to return true")
		}
		if account.CanLogin() {
			t.Error("expected CanLogin to return false when locked")
		}
	})

	t.Run("unlock account", func(t *testing.T) {
		account := createTestAccount(t, TypeInternal)
		account.FailedLoginAttempts = 5
		lockedTime := time.Now().Add(30 * time.Minute)
		account.LockedUntil = &lockedTime
		
		account.UnlockAccount()
		
		if account.FailedLoginAttempts != 0 {
			t.Error("expected failed attempts to be reset")
		}
		if account.LockedUntil != nil {
			t.Error("expected lockedUntil to be cleared")
		}
	})
}

func TestUserAccount_UpdateMethods(t *testing.T) {
	t.Run("update username", func(t *testing.T) {
		account := createTestAccount(t, TypeInternal)
		
		err := account.UpdateUsername("newusername")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if account.Username.Value() != "newusername" {
			t.Error("expected username to be updated")
		}
		
		// Try same username
		err = account.UpdateUsername("newusername")
		if err == nil {
			t.Error("expected error for same username")
		}

		// Try invalid username
		err = account.UpdateUsername("a")
		if err == nil {
			t.Error("expected error for too short username")
		}
	})

	t.Run("update email", func(t *testing.T) {
		account := createTestAccount(t, TypeExternal)
		
		err := account.UpdateEmail("newemail@example.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if account.Email.Value() != "newemail@example.com" {
			t.Error("expected email to be updated")
		}
		
		// Try same email
		err = account.UpdateEmail("newemail@example.com")
		if err == nil {
			t.Error("expected error for same email")
		}

		// Try invalid email
		err = account.UpdateEmail("not-an-email")
		if err == nil {
			t.Error("expected error for invalid email")
		}
	})

	t.Run("update password hash", func(t *testing.T) {
		account := createTestAccount(t, TypeMembership)
		
		err := account.UpdatePasswordHash("new_hashed_password")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		
		// Try empty password
		err = account.UpdatePasswordHash("")
		if err == nil {
			t.Error("expected error for empty password")
		}
	})

	t.Run("update type", func(t *testing.T) {
		account := createTestAccount(t, TypeExternal)
		
		err := account.UpdateType(TypeInternal)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if account.Type != TypeInternal {
			t.Error("expected type to be updated")
		}
		
		// Try same type
		err = account.UpdateType(TypeInternal)
		if err == nil {
			t.Error("expected error for same type")
		}
		
		// Try invalid type
		err = account.UpdateType("invalid")
		if err == nil {
			t.Error("expected error for invalid type")
		}
	})
}

func TestUserAccount_QueryMethods(t *testing.T) {
	t.Run("status checks", func(t *testing.T) {
		account := createTestAccount(t, TypeInternal)
		
		// Initial state
		if !account.IsPendingVerification() {
			t.Error("expected account to be pending verification")
		}
		
		// Active state
		account.Status = StatusActive
		if !account.IsActive() {
			t.Error("expected account to be active")
		}
		
		// Disabled state
		account.Status = StatusDisabled
		if !account.IsDisabled() {
			t.Error("expected account to be disabled")
		}
		
		// Deleted state
		account.Status = StatusDeleted
		if !account.IsSoftDeleted() {
			t.Error("expected account to be soft deleted")
		}
	})

	t.Run("disability type checks", func(t *testing.T) {
		account := createTestAccount(t, TypeExternal)
		account.Status = StatusDisabled
		
		// Inactive
		inactive := DisabilityTypeInactive
		account.DisabilityType = &inactive
		if !account.IsInactive() {
			t.Error("expected account to be inactive")
		}
		
		// Suspended
		suspended := DisabilityTypeSuspended
		account.DisabilityType = &suspended
		if !account.IsSuspended() {
			t.Error("expected account to be suspended")
		}
		
		// Blocked
		blocked := DisabilityTypeBlocked
		account.DisabilityType = &blocked
		if !account.IsBlocked() {
			t.Error("expected account to be blocked")
		}
		
		// Expired
		expired := DisabilityTypeExpired
		account.DisabilityType = &expired
		if !account.IsExpired() {
			t.Error("expected account to be expired")
		}
		
		// Violation
		violation := DisabilityTypeViolation
		account.DisabilityType = &violation
		if !account.HasViolation() {
			t.Error("expected account to have violation")
		}
		
		// Manual
		manual := DisabilityTypeManual
		account.DisabilityType = &manual
		if !account.IsManuallyDisabled() {
			t.Error("expected account to be manually disabled")
		}
	})

	t.Run("account type checks", func(t *testing.T) {
		tests := []struct {
			accountType UserAccountType
			checkFunc   func(*UserAccount) bool
			name        string
		}{
			{TypeInternal, (*UserAccount).IsInternal, "internal"},
			{TypeExternal, (*UserAccount).IsExternal, "external"},
			{TypeMembership, (*UserAccount).IsMembership, "membership"},
			{TypePartner, (*UserAccount).IsPartner, "partner"},
			{TypeDeveloper, (*UserAccount).IsDeveloper, "developer"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				account := createTestAccount(t, tt.accountType)
				if !tt.checkFunc(account) {
					t.Errorf("expected account to be %s", tt.name)
				}
			})
		}
	})

	t.Run("can login checks", func(t *testing.T) {
		account := createTestAccount(t, TypeMembership)
		
		// Cannot login when pending
		if account.CanLogin() {
			t.Error("expected pending account cannot login")
		}
		
		// Cannot login when unverified
		account.Status = StatusActive
		if account.CanLogin() {
			t.Error("expected unverified account cannot login")
		}
		
		// Can login when active and verified
		account.IsVerified = true
		if !account.CanLogin() {
			t.Error("expected active verified account can login")
		}
		
		// Cannot login when locked
		lockTime := time.Now().Add(30 * time.Minute)
		account.LockedUntil = &lockTime
		if account.CanLogin() {
			t.Error("expected locked account cannot login")
		}
		
		// Cannot login when disabled
		account.LockedUntil = nil
		account.Status = StatusDisabled
		if account.CanLogin() {
			t.Error("expected disabled account cannot login")
		}
	})
}

func TestUserAccount_ConvenienceMethods(t *testing.T) {
	tests := []struct {
		name        string
		accountType UserAccountType
		method      func(*UserAccount) error
		dtype       DisabilityType
	}{
		{
			name:        "set inactive internal",
			accountType: TypeInternal,
			method: func(ua *UserAccount) error {
				return ua.SetInactive("admin123", "dormant account")
			},
			dtype: DisabilityTypeInactive,
		},
		{
			name:        "suspend external",
			accountType: TypeExternal,
			method: func(ua *UserAccount) error {
				return ua.Suspend("admin123", "temporary suspension")
			},
			dtype: DisabilityTypeSuspended,
		},
		{
			name:        "block membership",
			accountType: TypeMembership,
			method: func(ua *UserAccount) error {
				return ua.Block("admin123", "permanent block")
			},
			dtype: DisabilityTypeBlocked,
		},
		{
			name:        "set expired partner",
			accountType: TypePartner,
			method: func(ua *UserAccount) error {
				return ua.SetExpired("system", "contract expired")
			},
			dtype: DisabilityTypeExpired,
		},
		{
			name:        "set violation external",
			accountType: TypeExternal,
			method: func(ua *UserAccount) error {
				return ua.SetViolation("admin123", "content violation")
			},
			dtype: DisabilityTypeViolation,
		},
		{
			name:        "disable manually developer",
			accountType: TypeDeveloper,
			method: func(ua *UserAccount) error {
				return ua.DisableManually("admin123", "manual action")
			},
			dtype: DisabilityTypeManual,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := createTestAccount(t, tt.accountType)
			account.Status = StatusActive
			account.IsVerified = true
			
			err := tt.method(account)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			
			if account.Status != StatusDisabled {
				t.Error("expected account to be disabled")
			}
			if account.DisabilityType == nil || *account.DisabilityType != tt.dtype {
				t.Errorf("expected disability type %s", tt.dtype)
			}
		})
	}
}

// Helper function to create test account with specific type
func createTestAccount(t *testing.T, accountType UserAccountType) *UserAccount {
	var registeredBy string
	if accountType == TypeMembership {
		registeredBy = SelfRegistration
	} else {
		registeredBy = "admin123"
	}

	account, err := NewUserAccountForTesting(
		"test123",
		"testuser",
		"test@example.com",
		"TestPassword123!",
		accountType,
		registeredBy,
	)
	if err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}
	return account
}