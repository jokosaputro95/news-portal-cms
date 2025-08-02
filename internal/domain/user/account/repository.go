package account

import (
	"context"

	"github.com/google/uuid"
)

type UserAccountFilter struct {
	SearchQuery string // Search in username, email, display name
	Status *UserAccountStatus
	Type *UserAccountType
	IsVerified *bool
	
	// Pagination
	Limit int
	Offset int

	// Sorting
	OrderBy string // "created_at", "username", "last_login_at"
	SortOrder string // "asc" or "desc"

}

type UserAccountRepository interface {
	// Commands
	Create(ctx context.Context, account *UserAccount) error
	Update(ctx context.Context, account *UserAccount) error
	Delete(ctx context.Context, id uuid.UUID) error // soft delete

	// Query - Single
	FindByID(ctx context.Context, id uuid.UUID) (*UserAccount, error)
	FindByUsername(ctx context.Context, username string) (*UserAccount, error)
	FindByEmail(ctx context.Context, email string) (*UserAccount, error)

	// Query - Multipe with filters
	Find(ctx context.Context, filter *UserAccountFilter) ([]*UserAccount, error)
	Count(ctx context.Context, filter *UserAccountFilter) (int64, error)
}