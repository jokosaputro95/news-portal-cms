package account

import (
	"testing"
)

// Helper: generate valid values
func validInputs() (id, username, email, password string) {
	return "user-id-1", "testuser", "user@example.com", "Password1!"
}

func TestNewUserAccountWithHash_Success(t *testing.T) {
	id, username, email, hash := "user-id-1", "testuser", "user@example.com", "hashed_pw"
	account, err := NewUserAccountWithHash(id, username, email, hash, TypeInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if account.ID != id {
		t.Errorf("expected ID '%s', got '%s'", id, account.ID)
	}
	if account.Username.String() != username {
		t.Errorf("expected username '%s', got '%s'", username, account.Username.String())
	}
	if account.Email.String() != email {
		t.Errorf("expected email '%s', got '%s'", email, account.Email.String())
	}
	if account.PasswordHash.Value() != hash {
		t.Errorf("expected password hash '%s', got '%s'", hash, account.PasswordHash.Value())
	}
	if account.Status != StatusPendingVerification {
		t.Errorf("expected status pending_verification, got '%s'", account.Status)
	}
}

func TestNewUserAccountWithHash_Invalid(t *testing.T) {
	// Empty ID
	_, err := NewUserAccountWithHash("", "testuser", "user@example.com", "hashed_pw", TypeInternal)
	if err == nil {
		t.Error("expected error for empty id")
	}
	// Invalid username
	_, err = NewUserAccountWithHash("id", "ab", "user@example.com", "hashed_pw", TypeInternal)
	if err == nil {
		t.Error("expected error for invalid username")
	}
	// Invalid email
	_, err = NewUserAccountWithHash("id", "testuser", "userexample.com", "hashed_pw", TypeInternal)
	if err == nil {
		t.Error("expected error for invalid email")
	}
	// Empty password hash
	_, err = NewUserAccountWithHash("id", "testuser", "user@example.com", "", TypeInternal)
	if err == nil {
		t.Error("expected error for empty password hash")
	}
}

func TestNewUserAccountForTesting_Success(t *testing.T) {
	id, username, email, password := validInputs()
	account, err := NewUserAccountForTesting(id, username, email, password, TypeInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if account.PasswordHash.Value() != "hashed_"+password {
		t.Errorf("expected password hash 'hashed_%s', got '%s'", password, account.PasswordHash.Value())
	}
}

func TestNewUserAccountForTesting_Invalid(t *testing.T) {
	// Invalid password (too short)
	_, err := NewUserAccountForTesting("id", "testuser", "user@example.com", "123", TypeInternal)
	if err == nil {
		t.Error("expected error for invalid password")
	}
}

func TestUserAccount_Verify(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)

	err := account.Verify("admin-1")
	if err != nil {
		t.Errorf("expected verify to succeed, got %v", err)
	}
	if !account.IsVerified {
		t.Error("expected account to be verified")
	}
	if account.Status != StatusActive {
		t.Error("expected account to be active after verification")
	}
	if account.VerifiedBy == nil || *account.VerifiedBy != "admin-1" {
		t.Error("expected VerifiedBy set to 'admin-1'")
	}
	if account.VerifiedAt == nil {
		t.Error("expected VerifiedAt to be set")
	}

	// Try verify again (should fail)
	err = account.Verify("admin-1")
	if err == nil {
		t.Error("expected error on already verified")
	}
}

func TestUserAccount_Activate_Disable_Block_Suspend_Reactivate_SetInactive(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)

	// Set as verified and active
	_ = account.Verify("admin-1")

	// Disable (block)
	err := account.Block("admin-2", "abuse")
	if err != nil {
		t.Fatalf("expected block to succeed, got %v", err)
	}
	if !account.IsBlocked() || account.Status != StatusDisabled {
		t.Error("expected account to be blocked and status disabled")
	}
	if account.DisabilityType == nil || *account.DisabilityType != DisabilityTypeBlocked {
		t.Error("expected DisabilityType to be blocked")
	}
	if account.IssuedReason == nil || *account.IssuedReason != "abuse" {
		t.Error("expected issued reason to be 'abuse'")
	}

	// Reactivate
	err = account.Reactivate("admin-3")
	if err != nil {
		t.Fatalf("expected reactivate to succeed, got %v", err)
	}
	if !account.IsActive() || account.Status != StatusActive {
		t.Error("expected account to be active after reactivate")
	}
	if account.DisabilityType != nil {
		t.Error("expected disability type to be cleared")
	}

	// Suspend
	_ = account.Suspend("admin-4", "suspend reason")
	if !account.IsSuspended() || account.Status != StatusDisabled {
		t.Error("expected account to be suspended and status disabled")
	}
	if account.DisabilityType == nil || *account.DisabilityType != DisabilityTypeSuspended {
		t.Error("expected DisabilityType to be suspended")
	}

	// SetInactive
	_ = account.SetInactive("admin-5", "inactive reason")
	if !account.IsInactive() {
		t.Error("expected account to be inactive")
	}
	t.Logf("Status: %v, DisabilityType: %v", account.Status, account.DisabilityType)
	if account.DisabilityType == nil || *account.DisabilityType != DisabilityTypeInactive {
		t.Error("expected DisabilityType to be inactive")
	}
}

func TestUserAccount_Delete(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)
	_ = account.Verify("admin-1")
	err := account.Delete("deleter-1")
	if err != nil {
		t.Fatalf("expected delete to succeed, got %v", err)
	}
	if !account.IsSoftDeleted() {
		t.Error("expected account to be soft deleted")
	}
	if account.DeletedBy == nil || *account.DeletedBy != "deleter-1" {
		t.Error("expected DeletedBy to be set")
	}
	if account.DeletedAt == nil {
		t.Error("expected DeletedAt to be set")
	}

	// Delete again (should fail)
	err = account.Delete("deleter-2")
	if err == nil {
		t.Error("expected error on already deleted account")
	}
}

func TestUserAccount_UpdateUsername_UpdateEmail_UpdatePasswordHash(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)

	// Update Username
	newUsername := "otheruser"
	err := account.UpdateUsername(newUsername)
	if err != nil {
		t.Errorf("expected update username to succeed, got %v", err)
	}
	if account.Username.String() != newUsername {
		t.Errorf("expected username to be updated to '%s'", newUsername)
	}
	// Try update to same username
	err = account.UpdateUsername(newUsername)
	if err == nil {
		t.Error("expected error updating to same username")
	}

	// Update Email
	newEmail := "other@example.com"
	err = account.UpdateEmail(newEmail)
	if err != nil {
		t.Errorf("expected update email to succeed, got %v", err)
	}
	if account.Email.String() != newEmail {
		t.Errorf("expected email to be updated to '%s'", newEmail)
	}
	// Try update to same email
	err = account.UpdateEmail(newEmail)
	if err == nil {
		t.Error("expected error updating to same email")
	}

	// Update PasswordHash
	newHash := "hashed_newpass"
	err = account.UpdatePasswordHash(newHash)
	if err != nil {
		t.Errorf("expected update password hash to succeed, got %v", err)
	}
	if account.PasswordHash.Value() != newHash {
		t.Errorf("expected password hash to be updated to '%s'", newHash)
	}
}

func TestUserAccount_UpdateStatus_UpdateType_UpdateIsVerified(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)

	// Update Status
	err := account.UpdateStatus(StatusActive)
	if err != nil {
		t.Errorf("expected update status to succeed, got %v", err)
	}
	if account.Status != StatusActive {
		t.Errorf("expected status to be updated to '%s'", StatusActive)
	}
	// Try update to same status
	err = account.UpdateStatus(StatusActive)
	if err == nil {
		t.Error("expected error updating to same status")
	}

	// Update Type
	err = account.UpdateType(TypeDeveloper)
	if err != nil {
		t.Errorf("expected update type to succeed, got %v", err)
	}
	if account.Type != TypeDeveloper {
		t.Errorf("expected type to be updated to '%s'", TypeDeveloper)
	}
	// Try update to same type
	err = account.UpdateType(TypeDeveloper)
	if err == nil {
		t.Error("expected error updating to same type")
	}

	// Update isVerified
	err = account.UpdateIsVerified(true)
	if err != nil {
		t.Errorf("expected update isVerified to succeed, got %v", err)
	}
	if !account.IsVerified {
		t.Error("expected IsVerified to be true")
	}
}

func TestUserAccount_QueryMethods(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeMembership)
	// Initial state
	if !account.IsPendingVerification() {
		t.Error("expected initial state to be pending verification")
	}
	_ = account.Verify("admin-1")
	if !account.CanLogin() {
		t.Error("expected CanLogin after verification and active")
	}
	if !account.IsActive() {
		t.Error("expected IsActive after verification")
	}
	_ = account.Block("admin-2", "abuse")
	if !account.IsBlocked() {
		t.Error("expected IsBlocked after block")
	}
	if account.GetDisabilityType() == nil || *account.GetDisabilityType() != DisabilityTypeBlocked {
		t.Error("expected GetDisabilityType to return DisabilityTypeBlocked")
	}
	if account.GetDisabilityReason() == nil || *account.GetDisabilityReason() != "abuse" {
		t.Error("expected GetDisabilityReason to be 'abuse'")
	}
	// Set inactive
	_ = account.SetInactive("admin-3", "dormant")
	if !account.IsInactive() {
		t.Error("expected IsInactive after set inactive")
	}
	if !account.IsDisabled() {
		t.Error("expected IsDisabled after set inactive")
	}
	// Type check
	if !account.IsMembership() {
		t.Error("expected IsMembership true")
	}
	if account.IsDeveloper() {
		t.Error("expected IsDeveloper false")
	}
	if account.IsExternal() {
		t.Error("expected IsExternal false")
	}
	if account.IsPartner() {
		t.Error("expected IsPartner false")
	}
	if account.IsInternal() {
		t.Error("expected IsInternal false")
	}
}

func TestUserAccount_Disable_Errors(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)
	_ = account.Verify("admin-1")
	// Already disabled
	_ = account.Block("admin-2", "abuse")
	err := account.Block("admin-2", "abuse again")
	if err == nil {
		t.Error("expected error when disabling already disabled account")
	}
	// Try to disable deleted account
	_ = account.Reactivate("admin-3")
	_ = account.Delete("deleter")
	err = account.Block("admin-4", "no effect")
	if err == nil {
		t.Error("expected error when disabling deleted account")
	}
}

func TestUserAccount_Activate_Errors(t *testing.T) {
	id, username, email, hash := validInputs()
	account, _ := NewUserAccountWithHash(id, username, email, hash, TypeInternal)
	_ = account.Verify("admin-1")
	// Try activate when not disabled
	err := account.Activate("admin-2")
	if err == nil {
		t.Error("expected error when activating account not disabled")
	}
}
