package api

import "hyperdrop/core/sharenamerule"

// cleanShareName is the share-name rule every client applies before it sends
// a name (core/sharenamerule). The server applies it itself rather than
// trusting a client to have: it bounds a title on the public /share page and
// the name a client gives the share's folder, zip or text file.
var cleanShareName = sharenamerule.Clean
