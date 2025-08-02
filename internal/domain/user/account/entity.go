package account

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type UserAccountStatus string

const (
    StatusPendingVerification UserAccountStatus = "pending_verification"
    StatusActive UserAccountStatus = "active"
    StatusInactive UserAccountStatus = "inactive"
    StatusSuspended UserAccountStatus = "suspended"
    StatusBlocked UserAccountStatus = "blocked"
    StatusDeleted UserAccountStatus = "deleted"
)

type UserAccountType string

const (
    TypeInternal UserAccountType = "internal" // Staff, editor, publisher
    TypeExternal UserAccountType = "external" // Contributor external content writter
    TypeMembership UserAccountType = "membership" // Membership
    TypePartner UserAccountType = "partner" // Partner or Mitra
    TypeDeveloper UserAccountType = "developer" // Developer
)

type UserAccount struct {
    // Core Identity & Auth Only
    ID uuid.UUID
    Username Username
    Email Email
    PasswordHash PasswordHash

    // Security & Status
    Status UserAccountStatus
    Type UserAccountType
    IsVerified bool
    VerifiedBy *uuid.UUID
    VerifiedAt *time.Time
    IssuedReason *string

    LastActionBy *uuid.UUID

    LastLoginAt *time.Time
    LastLoginIP *string
    FailedLoginAttempts int
    LastFailedLoginAttempt *time.Time
    LastFailedLoginIP *string
    LockedUntil *time.Time
    
    // Audit
    CreatedAt time.Time
    UpdatedAt time.Time
    DeletedAt *time.Time
    DeletedBy *uuid.UUID
}

// Constructor
func NewUserAccount(username, email, passwordHash string, accountType UserAccountType) (*UserAccount, error) {
    usernameObj, err := NewUsername(username)
    if err != nil {
        return nil, err
    }
    emailObj, err := NewEmail(email)
    if err != nil {
        return nil, err
    }
    if err := ValidatePassword(passwordHash); err != nil {
        return nil, err
    }
    now := time.Now()
    id := uuid.New()
    return &UserAccount{
        ID:           id,
        Username:     *usernameObj,
        Email:        *emailObj,
        PasswordHash: NewPasswordHash(passwordHash),
        Status:       StatusPendingVerification,
        Type:         accountType,
        IsVerified:   false,
        CreatedAt:    now,
        UpdatedAt:    now,
    }, nil
}

// Business Methods
func (ua *UserAccount) Verify(userID uuid.UUID) error {
    if ua.Status != StatusPendingVerification {
        return errors.New("user account is not pending verification")
    }
    now := time.Now()
    ua.IsVerified = true
    ua.VerifiedBy = &userID
    ua.VerifiedAt = &now
    ua.Status = StatusActive
    ua.UpdatedAt = now
    return nil
}

func (ua *UserAccount) Activate(userID uuid.UUID) error {
    if ua.Status != StatusInactive {
        return errors.New("user account is not inactive")
    }
    
    ua.Status = StatusActive
    ua.UpdatedAt = time.Now()
    ua.LastActionBy = &userID
    return nil
}

func (ua *UserAccount) Block(userID uuid.UUID, reason string) error {
    if ua.Status == StatusBlocked {
        return errors.New("user account is already blocked")
    }
    if reason == "" {
        return errors.New("reason for blocking cannot be empty")
    }
    now := time.Now()
    ua.Status = StatusBlocked
    ua.IssuedReason = &reason
    ua.UpdatedAt = now
    ua.LastActionBy = &userID
    return nil
}

func (ua *UserAccount) Suspend(userID uuid.UUID, reason string) error {
    if ua.Status != StatusActive {
        return errors.New("user account is not active, cannot be suspended")
    }

    if reason == "" {
        return errors.New("reason for suspension cannot be empty")
    }

    now := time.Now()
    ua.Status = StatusSuspended
    ua.IssuedReason = &reason
    ua.UpdatedAt = now
    ua.LastActionBy = &userID

    return nil
}

func (ua *UserAccount) Reactivate(userID uuid.UUID) error {
    if ua.Status != StatusSuspended && ua.Status != StatusBlocked {
        return errors.New("user account is not suspended or blocked, cannot be reactivated")
    }

    now := time.Now()
    ua.Status = StatusActive
    ua.UpdatedAt = now
    ua.LastActionBy = &userID

    return nil
}

func (ua *UserAccount) Delete(deletedBy uuid.UUID) error {
    if ua.Status == StatusDeleted {
        return errors.New("user account is already deleted")
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

func (ua *UserAccount) UpdatePassword(newPassword string) error {
    if err := ValidatePassword(newPassword); err != nil {
        return err
    }
    ua.PasswordHash = NewPasswordHash(newPassword)
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

func (ua *UserAccount) CanLogin() bool {
    return ua.Status == StatusActive && ua.IsVerified
}

func (ua *UserAccount) IsActive() bool {
    return ua.Status == StatusActive
}

func (ua *UserAccount) IsSuspended() bool {
    return ua.Status == StatusSuspended
}

func (ua *UserAccount) IsBlocked() bool {
    return ua.Status == StatusBlocked
}

func (ua *UserAccount) IsSoftDeleted() bool {
    return ua.Status == StatusDeleted
}

func (ua *UserAccount) IsPendingVerification() bool {
    return ua.Status == StatusPendingVerification
}

func (ua *UserAccount) IsInactive() bool {
    return ua.Status == StatusInactive
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