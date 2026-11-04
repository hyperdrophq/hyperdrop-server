package api

import (
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// Backend is what the API serves from: rows, bytes, and the server folders
// linked shares may point at.
type Backend struct {
	DB    *metadb.DB
	FS    *sharefs.FS
	Roots *linked.Roots // nil disables linked shares
}
