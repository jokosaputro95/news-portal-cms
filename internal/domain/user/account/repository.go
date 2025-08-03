package account

import (
	"context"
	"errors"
	"time"
)

type UserAccountFilter struct {
	SearchQuery    *string // Search in username, email, display name
	Status         *UserAccountStatus
	Type           *UserAccountType
	DisabilityType *DisabilityType // New filter for disability type
	IsVerified     *bool
	
	// Date range filters
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	
	// Pagination with validation
	Limit  int `validate:"min=1,max=100"`
	Offset int `validate:"min=0"`

	// Sorting with validation
	OrderBy   string `validate:"oneof=created_at username last_login_at email"`
	SortOrder string `validate:"oneof=asc desc"`
}

// Validate filter parameters
func (f *UserAccountFilter) Validate() error {
	if f.Limit <= 0 || f.Limit > 100 {
		return errors.New("limit must be between 1 and 100")
	}
	if f.Offset < 0 {
		return errors.New("offset must be non-negative")
	}
	
	validOrderBy := map[string]bool{
		"created_at": true, 
		"username": true, 
		"last_login_at": true, 
		"email": true,
		"updated_at": true,
	}
	if f.OrderBy != "" && !validOrderBy[f.OrderBy] {
		return errors.New("invalid order_by field")
	}
	
	if f.SortOrder != "" && f.SortOrder != "asc" && f.SortOrder != "desc" {
		return errors.New("sort_order must be 'asc' or 'desc'")
	}
	
	// Validate date range
	if f.CreatedAfter != nil && f.CreatedBefore != nil {
		if f.CreatedAfter.After(*f.CreatedBefore) {
			return errors.New("created_after must be before created_before")
		}
	}
	
	return nil
}

// Set default values for pagination and sorting
func (f *UserAccountFilter) SetDefaults() {
	if f.Limit == 0 {
		f.Limit = 20
	}
	if f.OrderBy == "" {
		f.OrderBy = "created_at"
	}
	if f.SortOrder == "" {
		f.SortOrder = "desc"
	}
}

type UserAccountRepository interface {
	// Commands
	Create(ctx context.Context, account *UserAccount) error
	Update(ctx context.Context, account *UserAccount) error
	Delete(ctx context.Context, id string) error // soft delete

	// Query - Single
	FindByID(ctx context.Context, id string) (*UserAccount, error)
	FindByUsername(ctx context.Context, username string) (*UserAccount, error)
	FindByEmail(ctx context.Context, email string) (*UserAccount, error)

	// Query - Multiple with filters
	Find(ctx context.Context, filter *UserAccountFilter) ([]*UserAccount, error)
	Count(ctx context.Context, filter *UserAccountFilter) (int64, error)
	
	// Existence checks
	ExistsByID(ctx context.Context, id string) (bool, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	
	// Specialized queries
	FindActiveByEmail(ctx context.Context, email string) (*UserAccount, error)
	FindVerifiedByUsername(ctx context.Context, username string) (*UserAccount, error)
	FindExpiredAccounts(ctx context.Context, expiredBefore time.Time) ([]*UserAccount, error)
	FindAccountsForCleanup(ctx context.Context, deletedBefore time.Time) ([]*UserAccount, error)
	
	// Disability-specific queries
	FindDisabledAccounts(ctx context.Context, disabilityType *DisabilityType) ([]*UserAccount, error)
	FindSuspendedAccounts(ctx context.Context) ([]*UserAccount, error)
	FindBlockedAccounts(ctx context.Context) ([]*UserAccount, error)
	FindInactiveAccounts(ctx context.Context, inactiveSince time.Time) ([]*UserAccount, error)
}