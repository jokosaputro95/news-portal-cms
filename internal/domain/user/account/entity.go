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
	StatusDisabled            UserAccountStatus = "disabled"
	StatusDeleted             UserAccountStatus = "deleted"
)

type DisabilityType string

const (
	DisabilityTypeInactive  DisabilityType = "inactive"
	DisabilityTypeSuspended DisabilityType = "suspended"
	DisabilityTypeBlocked   DisabilityType = "blocked"
	DisabilityTypeManual    DisabilityType = "manual"
	DisabilityTypeExpired   DisabilityType = "expired"
	DisabilityTypeViolation DisabilityType = "violation"
)

type UserAccountType string

const (
	TypeInternal   UserAccountType = "internal"
	TypeExternal   UserAccountType = "external"
	TypeMembership UserAccountType = "membership"
	TypePartner    UserAccountType = "partner"
	TypeDeveloper  UserAccountType = "developer"
)

// Special constants for registration
const (
	SelfRegistration = "self"
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
	RegisteredBy   *string // Can be user ID, "self", or system identifier

	DisabilityType *DisabilityType
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
func NewUserAccountWithHash(id, username, email, hashedPassword string, accountType UserAccountType, registeredBy string) (*UserAccount, error) {
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

	if err := validateAccountType(accountType); err != nil {
		return nil, err
	}

	if strings.TrimSpace(registeredBy) == "" {
		return nil, errors.New("registeredBy cannot be empty")
	}

	now := time.Now()
	return &UserAccount{
		ID:           id,
		Username:     *usernameObj,
		Email:        *emailObj,
		PasswordHash: NewPasswordHash(hashedPassword),
		Status:       StatusPendingVerification,
		Type:         accountType,
		RegisteredBy: &registeredBy,
		IsVerified:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Constructor for testing (receives raw password)
func NewUserAccountForTesting(id, username, email, rawPassword string, accountType UserAccountType, registeredBy string) (*UserAccount, error) {
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

	if err := validateAccountType(accountType); err != nil {
		return nil, err
	}

	if strings.TrimSpace(registeredBy) == "" {
		return nil, errors.New("registeredBy cannot be empty")
	}

	now := time.Now()
	return &UserAccount{
		ID:           id,
		Username:     *usernameObj,
		Email:        *emailObj,
		PasswordHash: NewPasswordHash("hashed_" + rawPassword), // Simple hash for testing
		Status:       StatusPendingVerification,
		Type:         accountType,
		RegisteredBy: &registeredBy,
		IsVerified:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Constructor for self-registration (membership type)
func NewUserAccountForSelfRegistration(id, username, email, hashedPassword string) (*UserAccount, error) {
	return NewUserAccountWithHash(id, username, email, hashedPassword, TypeMembership, SelfRegistration)
}

// Business Methods

// Verify marks account as verified and active
func (ua *UserAccount) Verify(verifierID string) error {
	if ua.Status != StatusPendingVerification {
		return errors.New("user account is not pending verification")
	}
	if ua.IsVerified {
		return errors.New("user account is already verified")
	}
	if strings.TrimSpace(verifierID) == "" {
		return errors.New("verifier ID cannot be empty")
	}

	now := time.Now()
	ua.IsVerified = true
	ua.VerifiedBy = &verifierID
	ua.VerifiedAt = &now
	ua.Status = StatusActive
	ua.UpdatedAt = now
	ua.LastActionBy = &verifierID
	return nil
}

// SelfVerify for email verification or similar self-service verification
func (ua *UserAccount) SelfVerify() error {
	if ua.Status != StatusPendingVerification {
		return errors.New("user account is not pending verification")
	}
	if ua.IsVerified {
		return errors.New("user account is already verified")
	}
	// Self-verification only allowed for membership type
	if ua.Type != TypeMembership {
		return errors.New("self-verification only allowed for membership accounts")
	}

	now := time.Now()
	verifier := SelfRegistration
	ua.IsVerified = true
	ua.VerifiedBy = &verifier
	ua.VerifiedAt = &now
	ua.Status = StatusActive
	ua.UpdatedAt = now
	ua.LastActionBy = &verifier
	return nil
}

// Activate activates a disabled account
func (ua *UserAccount) Activate(activatorID string) error {
	if ua.Status != StatusDisabled {
		return errors.New("user account is not disabled")
	}
	if strings.TrimSpace(activatorID) == "" {
		return errors.New("activator ID cannot be empty")
	}

	ua.Status = StatusActive
	ua.DisabilityType = nil
	ua.IssuedReason = nil
	ua.UpdatedAt = time.Now()
	ua.LastActionBy = &activatorID
	return nil
}

// Disable disables account with specific type and reason
func (ua *UserAccount) Disable(disablerID string, disabilityType DisabilityType, reason string) error {
	if ua.Status == StatusDeleted {
		return errors.New("cannot disable deleted account")
	}
	if ua.Status == StatusPendingVerification {
		return errors.New("cannot disable unverified account")
	}
	if ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == disabilityType {
		return errors.New("user account is already disabled with the same type")
	}
	if strings.TrimSpace(disablerID) == "" {
		return errors.New("disabler ID cannot be empty")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("reason cannot be empty")
	}
	if err := validateDisabilityType(disabilityType); err != nil {
		return err
	}

	now := time.Now()
	ua.Status = StatusDisabled
	ua.DisabilityType = &disabilityType
	ua.IssuedReason = &reason
	ua.UpdatedAt = now
	ua.LastActionBy = &disablerID
	return nil
}

// Convenience methods for specific disability types
func (ua *UserAccount) SetInactive(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeInactive, reason)
}

func (ua *UserAccount) Suspend(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeSuspended, reason)
}

func (ua *UserAccount) Block(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeBlocked, reason)
}

func (ua *UserAccount) SetExpired(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeExpired, reason)
}

func (ua *UserAccount) SetViolation(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeViolation, reason)
}

func (ua *UserAccount) DisableManually(userID string, reason string) error {
	return ua.Disable(userID, DisabilityTypeManual, reason)
}

// Reactivate reactivates a disabled account
func (ua *UserAccount) Reactivate(reactivatorID string) error {
	if ua.Status != StatusDisabled {
		return errors.New("user account is not disabled, cannot be reactivated")
	}
	if strings.TrimSpace(reactivatorID) == "" {
		return errors.New("reactivator ID cannot be empty")
	}

	now := time.Now()
	ua.Status = StatusActive
	ua.DisabilityType = nil
	ua.IssuedReason = nil
	ua.UpdatedAt = now
	ua.LastActionBy = &reactivatorID
	return nil
}

// Delete soft deletes the account
func (ua *UserAccount) Delete(deleterID string) error {
	if ua.Status == StatusDeleted {
		return errors.New("user account is already deleted")
	}
	if strings.TrimSpace(deleterID) == "" {
		return errors.New("deleter ID cannot be empty")
	}

	now := time.Now()
	ua.Status = StatusDeleted
	ua.DeletedAt = &now
	ua.DeletedBy = &deleterID
	ua.UpdatedAt = now
	ua.LastActionBy = &deleterID
	return nil
}

// Update Methods

func (ua *UserAccount) UpdateUsername(newUsername string) error {
	newUsernameObj, err := NewUsername(newUsername)
	if err != nil {
		return err
	}
	if ua.Username.Equals(*newUsernameObj) {
		return errors.New("new username is the same as current username")
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
		return errors.New("new email is the same as current email")
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

func (ua *UserAccount) UpdateType(newType UserAccountType) error {
	if ua.Type == newType {
		return errors.New("new type is the same as current type")
	}
	if err := validateAccountType(newType); err != nil {
		return err
	}
	ua.Type = newType
	ua.UpdatedAt = time.Now()
	return nil
}

// Login tracking methods

func (ua *UserAccount) RecordSuccessfulLogin(ipAddress string) error {
	if strings.TrimSpace(ipAddress) == "" {
		return errors.New("IP address cannot be empty")
	}
	now := time.Now()
	ua.LastLoginAt = &now
	ua.LastLoginIP = &ipAddress
	ua.FailedLoginAttempts = 0
	ua.LockedUntil = nil
	ua.UpdatedAt = now
	return nil
}

func (ua *UserAccount) RecordFailedLogin(ipAddress string, maxAttempts int, lockDuration time.Duration) error {
	if strings.TrimSpace(ipAddress) == "" {
		return errors.New("IP address cannot be empty")
	}
	if maxAttempts <= 0 {
		return errors.New("max attempts must be greater than 0")
	}

	now := time.Now()
	ua.FailedLoginAttempts++
	ua.LastFailedLoginAttempt = &now
	ua.LastFailedLoginIP = &ipAddress

	if ua.FailedLoginAttempts >= maxAttempts {
		lockedUntil := now.Add(lockDuration)
		ua.LockedUntil = &lockedUntil
	}

	ua.UpdatedAt = now
	return nil
}

func (ua *UserAccount) UnlockAccount() {
	ua.FailedLoginAttempts = 0
	ua.LockedUntil = nil
	ua.UpdatedAt = time.Now()
}

// Query Methods

func (ua *UserAccount) CanLogin() bool {
	if ua.Status != StatusActive || !ua.IsVerified {
		return false
	}
	if ua.LockedUntil != nil && time.Now().Before(*ua.LockedUntil) {
		return false
	}
	return true
}

func (ua *UserAccount) IsLocked() bool {
	return ua.LockedUntil != nil && time.Now().Before(*ua.LockedUntil)
}

func (ua *UserAccount) IsActive() bool {
	return ua.Status == StatusActive
}

func (ua *UserAccount) IsDisabled() bool {
	return ua.Status == StatusDisabled
}

func (ua *UserAccount) IsSoftDeleted() bool {
	return ua.Status == StatusDeleted
}

func (ua *UserAccount) IsPendingVerification() bool {
	return ua.Status == StatusPendingVerification
}

// Disability type checks
func (ua *UserAccount) IsInactive() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeInactive
}

func (ua *UserAccount) IsSuspended() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeSuspended
}

func (ua *UserAccount) IsBlocked() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeBlocked
}

func (ua *UserAccount) IsExpired() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeExpired
}

func (ua *UserAccount) HasViolation() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeViolation
}

func (ua *UserAccount) IsManuallyDisabled() bool {
	return ua.Status == StatusDisabled && ua.DisabilityType != nil && *ua.DisabilityType == DisabilityTypeManual
}

// Account type checks
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

// Registration checks
func (ua *UserAccount) IsSelfRegistered() bool {
	return ua.RegisteredBy != nil && *ua.RegisteredBy == SelfRegistration
}

// Helper methods
func (ua *UserAccount) GetDisabilityType() *DisabilityType {
	return ua.DisabilityType
}

func (ua *UserAccount) GetDisabilityReason() *string {
	if ua.Status == StatusDisabled {
		return ua.IssuedReason
	}
	return nil
}

// Domain Validation Functions

func validateAccountType(accountType UserAccountType) error {
	validTypes := map[UserAccountType]bool{
		TypeInternal:   true,
		TypeExternal:   true,
		TypeMembership: true,
		TypePartner:    true,
		TypeDeveloper:  true,
	}
	if !validTypes[accountType] {
		return errors.New("invalid account type")
	}
	return nil
}

func validateDisabilityType(disabilityType DisabilityType) error {
	validTypes := map[DisabilityType]bool{
		DisabilityTypeInactive:  true,
		DisabilityTypeSuspended: true,
		DisabilityTypeBlocked:   true,
		DisabilityTypeManual:    true,
		DisabilityTypeExpired:   true,
		DisabilityTypeViolation: true,
	}
	if !validTypes[disabilityType] {
		return errors.New("invalid disability type")
	}
	return nil
}