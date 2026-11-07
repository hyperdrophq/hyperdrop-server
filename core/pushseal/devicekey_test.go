package pushseal

import "testing"

func TestADeviceKeyOpensWhatIsSealedToItsPublicHalf(t *testing.T) {
	priv, pub, err := NewDeviceKey()
	if err != nil || len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("%d %d %v", len(priv), len(pub), err)
	}
	if again, err := PublicKeyOf(priv); err != nil || string(again) != string(pub) {
		t.Fatalf("PublicKeyOf disagrees: %v", err)
	}
	sealed, err := Seal(pub, Message{V: 1, Kind: "inboxReceived", Title: "Files received", Body: "Received 2 files", Thread: "inbox-1", Tag: "entry-1", Unseen: 2})
	if err != nil {
		t.Fatal(err)
	}
	m, err := OpenRaw(priv, sealed)
	if err != nil || m.Kind != "inboxReceived" || m.Unseen != 2 || m.Tag != "entry-1" {
		t.Fatalf("%+v %v", m, err)
	}
	other, _, _ := NewDeviceKey()
	if _, err := OpenRaw(other, sealed); err == nil {
		t.Fatal("another key opened the message")
	}
	if _, err := OpenRaw(priv, sealed[:len(sealed)-8]+"AAAAAAA="); err == nil {
		t.Fatal("a damaged ciphertext opened")
	}
	if _, err := OpenRaw([]byte("short"), sealed); err == nil {
		t.Fatal("a 5-byte key was accepted")
	}
}
