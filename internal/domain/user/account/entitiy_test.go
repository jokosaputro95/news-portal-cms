package account

import (
	"testing"

	"github.com/google/uuid"
)

// Helper: generate valid input
func validAccountInputs() (string, string, string) {
	return "joko_saputro95", "user@example.com", "Password1!"
}

func TestNewUserAccount_Success(t *testing.T) {
	username, email, password := validAccountInputs()
	account, err := NewUserAccount(username, email, password, TypeInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if account.Username.value != username {
		t.Errorf("expected username '%s', got '%s'", username, account.Username.value)
	}
	if account.Email.value != email {
		t.Errorf("expected email '%s', got '%s'", email, account.Email.value)
	}
	if account.Status != StatusPendingVerification {
		t.Errorf("expected status %v, got %v", StatusPendingVerification, account.Status)
	}
}

func TestNewUserAccount_Invalid(t *testing.T) {
	_, err := NewUserAccount("ab", "user@example.com", "Password1!", TypeInternal)
	if err == nil {
		t.Error("expected error for invalid username, got nil")
	}
	_, err = NewUserAccount("joko", "wrong-email", "Password1!", TypeInternal)
	if err == nil {
		t.Error("expected error for invalid email, got nil")
	}
	_, err = NewUserAccount("joko", "user@example.com", "weak", TypeInternal)
	if err == nil {
		t.Error("expected error for invalid password, got nil")
	}
}

func TestUserAccount_Verify(t *testing.T) {
	username, email, password := validAccountInputs()
	account, _ := NewUserAccount(username, email, password, TypeInternal)
	verifierID := uuid.New()
	if err := account.Verify(verifierID); err != nil {
		t.Fatalf("expected verify success, got error: %v", err)
	}
	if !account.IsVerified {
		t.Error("expected account to be verified")
	}
	if account.Status != StatusActive {
		t.Error("expected status to be active after verification")
	}
	if account.VerifiedBy == nil || *account.VerifiedBy != verifierID {
		t.Error("expected VerifiedBy to be set")
	}
	if account.VerifiedAt == nil {
		t.Error("expected VerifiedAt to be set")
	}
}

func TestUserAccount_Block_Suspend_Reactive(t *testing.T) {
	username, email, password := validAccountInputs()
	account, _ := NewUserAccount(username, email, password, TypeInternal)
	verifierID := uuid.New()
	account.Verify(verifierID)
	blockerID := uuid.New()
	reason := "violation"
	if err := account.Block(blockerID, reason); err != nil {
		t.Errorf("Block failed: %v", err)
	}
	if account.Status != StatusBlocked {
		t.Error("expected status Blocked")
	}
	if account.IssuedReason == nil || *account.IssuedReason != reason {
		t.Error("expected IssuedReason to be set")
	}
	// Reactivate
	if err := account.Reactivate(verifierID); err != nil {
		t.Errorf("Reactivate failed: %v", err)
	}
	if account.Status != StatusActive {
		t.Error("expected status Active after reactivation")
	}
}

func TestUserAccount_UpdateEmail_Username(t *testing.T) {
	username, email, password := validAccountInputs()
	account, _ := NewUserAccount(username, email, password, TypeInternal)
	if err := account.UpdateUsername("new_username"); err != nil {
		t.Errorf("UpdateUsername failed: %v", err)
	}
	if account.Username.value != "new_username" {
		t.Error("expected updated username")
	}
	if err := account.UpdateEmail("newuser@email.com"); err != nil {
		t.Errorf("UpdateEmail failed: %v", err)
	}
	if account.Email.value != "newuser@email.com" {
		t.Error("expected updated email")
	}
}

func TestUserAccount_CanLogin(t *testing.T) {
	username, email, password := validAccountInputs()
	account, _ := NewUserAccount(username, email, password, TypeInternal)
	if account.CanLogin() {
		t.Error("should not login before verification")
	}
	account.IsVerified = true
	account.Status = StatusActive
	if !account.CanLogin() {
		t.Error("should be able to login after verified & active")
	}
}
