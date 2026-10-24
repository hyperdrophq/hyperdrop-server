package sharefs

import (
	"io"
	"sync"
)

// inflightBytes counts, per share and path, the bytes ranged chunks have
// written but not yet recorded: a chunk's range reaches the sidecar only
// after its bytes sync, so without this a 32 MiB chunk reads as nothing
// until its last byte lands. It is progress for the waiting page only;
// what counts as received is the sidecar.
type inflightBytes struct {
	mu sync.Mutex
	m  map[string]int64
}

func inflightKey(id, rel string) string { return id + "\x00" + rel }

func (b *inflightBytes) add(key string, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]int64{}
	}
	b.m[key] += n
	if b.m[key] <= 0 {
		delete(b.m, key)
	}
}

func (b *inflightBytes) get(key string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.m[key]
}

// countingWriter adds every byte it writes to its chunk's in-flight count
// and remembers how many, so the chunk can take them back.
type countingWriter struct {
	w     io.Writer
	b     *inflightBytes
	key   string
	added int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.b.add(c.key, int64(n))
		c.added += int64(n)
	}
	return n, err
}

// release takes the chunk's bytes back out of the in-flight count.
func (c *countingWriter) release() {
	if c.added > 0 {
		c.b.add(c.key, -c.added)
		c.added = 0
	}
}
