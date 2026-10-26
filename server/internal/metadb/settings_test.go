package metadb

import "testing"

func TestASettingIsKeptApartFromTheDatabasesOwnKeys(t *testing.T) {
	db := openTest(t)
	if _, ok, err := db.Setting("selfupdate.auto"); err != nil || ok {
		t.Fatalf("absent: %v %v", ok, err)
	}
	wake, stop := db.Subscribe()
	defer stop()
	if err := db.SetSetting("selfupdate.auto", "off"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("selfupdate.auto", "off2"); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := db.Setting("selfupdate.auto"); err != nil || !ok || v != "off2" {
		t.Fatalf("got %q %v %v", v, ok, err)
	}
	if _, ok, _ := db.Setting(prunedKey); ok {
		t.Fatal("a setting read reached the database's own key")
	}
	select {
	case <-wake:
		t.Fatal("a setting write woke the share subscribers")
	default:
	}
	if err := db.DeleteSetting("selfupdate.auto"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.Setting("selfupdate.auto"); ok {
		t.Fatal("deleted setting still there")
	}
}
