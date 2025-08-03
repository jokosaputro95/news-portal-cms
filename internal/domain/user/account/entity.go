package account

import (
	"errors"
	"strings"
	"time"
)

type UserAccountStatus string

const (
	StatusPendingVerification UserAccountStatus = "pending_verification"
	StatusActive              UserAccountStatus = "active"
	StatusDisabled            UserAccountStatus = "disabled" // Merge dari inactive/suspended/blocked
	StatusDeleted             UserAccountStatus = "deleted"
)

// Disability type untuk granularity
type DisabilityType string

const (
	DisabilityTypeInactive  DisabilityType = "inactive"   // Account not used/dormant
	DisabilityTypeSuspended DisabilityType = "suspended"  // Temporary suspension
	DisabilityTypeBlocked   DisabilityType = "blocked"    // Permanently blocked
	DisabilityTypeManual    DisabilityType = "manual"     // Manually disabled by admin
)

type UserAccountType string

const (
	TypeInternal   UserAccountType = "internal"   // Staff, editor, publisher
	TypeExternal   UserAccountType = "external"   // Contributor external content writer
	TypeMembership UserAccountType = "membership" // Membership
	TypePartner    UserAccountType = "partner"    // Partner or Mitra
	TypeDeveloper  UserAccountType = "developer"  // Developer
)

type UserAccount struct {
	// Core Identity & Auth Only
	ID           string
	Username     Username
	Email        Email
	PasswordHash PasswordHash

	// Security & Status
	Status         UserAccountStatus
	Type           UserAccountType
	DisabilityType *DisabilityType // New field for granular disability tracking
	IsVerified     bool
	VerifiedBy     *string
	VerifiedAt     *time.Time
	IssuedReason   *string

	LastActionBy *string

	LastLoginAt            *time.Time
	LastLoginIP            *string
	FailedLoginAttempts    int
	LastFailedLoginAttempt *time.Time
	LastFailedLoginIP      *string
	LockedUntil            *time.Time

	// Audit
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
	DeletedBy *string
}

// Constructor for production (receives pre-generated ID and hashed password)
func NewUserAccountWithHash(id, username, email, hashedPassword string, accountType UserAccountType) (*UserAccount, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("ID cannot be empty")
	}

	usernameObj, err := NewUsername(username)
	if err != nil {
		return nil, err
	}
	emailObj, err := NewEmail(email)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(hashedPassword) == "" {
		return nil, errors.New("password hash cannot be empty")
	}

	now := time.Now()
	return &UserAccount{
		ID:           id,
		Username:     *usernameObj,
		Email:        *emailObj,
		PasswordHash: NewPasswordHash(hashedPassword),
		Status:       StatusPendingVerification,
		Type:         accountType,
		IsVerified:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Constructor for testing (receives raw password)
func NewUserAccountForTesting(id, username, email, rawPassword string, accountType UserAccountType) (*UserAccount, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("ID cannot be empty")
	}

	usernameObj, err := NewUsername(username)
	if err != nil {
		return nil, err
	}
	emailObj, err := NewEmail(email)
	if err != nil {
		return nil, err
	}

	if err := ValidatePassword(rawPassword); err != nil {
		return nil, err
	}

	now := time.Now()
	return &UserAccount{
		ID:           id,
		Username:     *usernameObj,
		Email:        *emailObj,
		PasswordHash: NewPasswordHash("hashed_" + rawPassword), // Simple hash for testing
		Status:       StatusPendingVerification,
		Type:         accountType,
		IsVerified:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Business Methods
func (ua *UserAccount) Verify(userID string) error {
	if ua.Status != StatusPendingVerification {
		return errors.New("user account is not pending verification")
	}
	if ua.IsVerified {
		return errors.New("user account is already verified")
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("verifier ID cannot be empty")
	}

	now := time.Now()
	ua.IsVerified = true
	ua.VerifiedBy = &userID
	ua.VerifiedAt = &now
	ua.Status = StatusActive
	ua.UpdatedAt = now
	return nil
}

func (ua *UserAccount) Activate(userID string) error {
	if ua.Status != StatusDisabled {
		return errors.New("user account is not disabled")
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("activator ID cannot be empty")
	}

	ua.Status = StatusActive
	ua.DisabilityType = nil // Clear disability type
	ua.IssuedReason = nil   // Clear reason
	ua.UpdatedAt = time.Now()
	ua.LastActionBy = &userID
	return nil
}

func (ua *UserAccount) Disable(userID string, disabilityType DisabilityType, reason string) error {
	if ua.Status == StatusDeleted {
		return errors.New("cannot disable deleted account")
	}
	if reason == "" {
		return errors.New("reason for disabling cannot be empty")
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("disabler ID cannot be empty")
	}

    if ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == disabilityType {
        return errors.New("user account is already disabled with the same type")
    }
    
	now := time.Now()
	ua.Status = StatusDisabled
	ua.DisabilityType = &disabilityType
	ua.IssuedReason = &reason
	ua.UpdatedAt = now
	ua.LastActionBy = &userID
	return nil
}

// Convenience methods for specific disability types
func (ua *UserAccount) Block(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeBlocked, reason)
}

func (ua *UserAccount) Suspend(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeSuspended, reason)
}

func (ua *UserAccount) SetInactive(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeInactive, reason)
}

func (ua *UserAccount) Reactivate(userID string) error {
	if ua.Status != StatusDisabled {
		return errors.New("user account is not disabled, cannot be reactivated")
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("reactivator ID cannot be empty")
	}

	now := time.Now()
	ua.Status = StatusActive
	ua.DisabilityType = nil // Clear disability type
	ua.UpdatedAt = now
	ua.LastActionBy = &userID
	ua.IssuedReason = nil // Clear the issued reason

	return nil
}

func (ua *UserAccount) Delete(deletedBy string) error {
	if ua.Status == StatusDeleted {
		return errors.New("user account is already deleted")
	}
	if strings.TrimSpace(deletedBy) == "" {
		return errors.New("deleter ID cannot be empty")
	}

	now := time.Now()
	ua.Status = StatusDeleted
	ua.DeletedAt = &now
	ua.DeletedBy = &deletedBy
	ua.UpdatedAt = now

	return nil
}

func (ua *UserAccount) UpdateUsername(newUsername string) error {
	newUsernameObj, err := NewUsername(newUsername)
	if err != nil {
		return err
	}
	if ua.Username.Equals(*newUsernameObj) {
		return errors.New("new username is the same as the current username")
	}
	ua.Username = *newUsernameObj
	ua.UpdatedAt = time.Now()
	return nil
}

func (ua *UserAccount) UpdateEmail(newEmail string) error {
	newEmailObj, err := NewEmail(newEmail)
	if err != nil {
		return err
	}

	if ua.Email.Equals(*newEmailObj) {
		return errors.New("new email is the same as the current email")
	}

	ua.Email = *newEmailObj
	ua.UpdatedAt = time.Now()
	return nil
}

func (ua *UserAccount) UpdatePasswordHash(hashedPassword string) error {
	if strings.TrimSpace(hashedPassword) == "" {
		return errors.New("password hash cannot be empty")
	}
	ua.PasswordHash = NewPasswordHash(hashedPassword)
	ua.UpdatedAt = time.Now()
	return nil
}

func (ua *UserAccount) UpdateStatus(newStatus UserAccountStatus) error {
	if ua.Status == newStatus {
		return errors.New("new status is the same as the current status")
	}
	ua.Status = newStatus
	ua.UpdatedAt = time.Now()
	return nil
}

func (ua *UserAccount) UpdateType(newType UserAccountType) error {
	if ua.Type == newType {
		return errors.New("new type is the same as the current type")
	}
	ua.Type = newType
	ua.UpdatedAt = time.Now()
	return nil
}

func (ua *UserAccount) UpdateIsVerified(newIsVerified bool) error {
	ua.IsVerified = newIsVerified
	ua.UpdatedAt = time.Now()
	return nil
}

// Query Methods
func (ua *UserAccount) CanLogin() bool {
	return ua.Status == StatusActive && ua.IsVerified
}

func (ua *UserAccount) IsActive() bool {
	return ua.Status == StatusActive
}

func (ua *UserAccount) IsDisabled() bool {
	return ua.Status == StatusDisabled
}

func (ua *UserAccount) IsSuspended() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeSuspended
}

func (ua *UserAccount) IsBlocked() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeBlocked
}

func (ua *UserAccount) IsInactive() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeInactive
}

func (ua *UserAccount) IsManuallyDisabled() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeManual
}

func (ua *UserAccount) IsSoftDeleted() bool {
	return ua.Status == StatusDeleted
}

func (ua *UserAccount) IsPendingVerification() bool {
	return ua.Status == StatusPendingVerification
}

func (ua *UserAccount) IsInternal() bool {
	return ua.Type == TypeInternal
}

func (ua *UserAccount) IsExternal() bool {
	return ua.Type == TypeExternal
}

func (ua *UserAccount) IsMembership() bool {
	return ua.Type == TypeMembership
}

func (ua *UserAccount) IsPartner() bool {
	return ua.Type == TypePartner
}

func (ua *UserAccount) IsDeveloper() bool {
	return ua.Type == TypeDeveloper
}

// Get disability details
func (ua *UserAccount) GetDisabilityType() *DisabilityType {
	return ua.DisabilityType
}

func (ua *UserAccount) GetDisabilityReason() *string {
	if ua.Status == StatusDisabled {
		return ua.IssuedReason
	}
	return nil
}