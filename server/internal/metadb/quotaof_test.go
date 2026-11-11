package metadb

import (
	"errors"
	"testing"
)

func TestQuotaOfReadsTheAccountsQuota(t *testing.T) {
	db := openTest(t)
	quota := int64(1 << 20)
	if _, err := db.CreateUser("bob", "a-long-password", RoleUser, Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	if got, err := db.QuotaOf("bob"); err != nil || got != quota {
		t.Fatalf("= %d, %v, want %d", got, err, quota)
	}
	if _, err := db.QuotaOf("nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("an unknown account: %v", err)
	}
}
