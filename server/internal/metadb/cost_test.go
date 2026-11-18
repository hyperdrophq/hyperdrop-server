package metadb

import "golang.org/x/crypto/bcrypt"

// The tests hash at bcrypt's cheapest cost: a fixture password is not a
// security boundary, and BcryptCost's own work would multiply the suite's time.
func init() {
	BcryptCost = bcrypt.MinCost
}
