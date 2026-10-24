package api

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// benchPayload builds `size` bytes of representative content: `ratio` of it
// highly compressible text, the remainder incompressible.
func benchPayload(b *testing.B, size int, compressible bool) []byte {
	b.Helper()
	if !compressible {
		buf := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			b.Fatal(err)
		}
		return buf
	}
	line := []byte("2026-07-26T11:02:14Z INFO  request served id=abc123 status=200 dur=4ms\n")
	return bytes.Repeat(line, size/len(line)+1)[:size]
}

func zstdEncode(b *testing.B, data []byte) []byte {
	b.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := zw.Write(data); err != nil {
		b.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

// BenchmarkUploadDecode measures the upload path's zstd decode: the pooled
// single-concurrency decoder from api.go, reading exactly as uploadFile does.
// Reported b/s are ORIGINAL bytes per second, i.e. the rate at which a
// compressed upload can be turned back into stored content.
//
// MEASURED 2026-07-26, Apple M5 Max (18 threads), -benchtime 2s -count 2:
//
//	text/8MiB            ~14.6 GB/s
//	incompressible/8MiB  ~12.7 GB/s   (a stored frame is nearly a memcpy)
//	text/64KiB            ~3.5 GB/s   (per-request overhead, not throughput)
//	Parallel (18 procs)  ~116 GB/s aggregate, and it scales linearly with cores
//
// Conclusion, which is why there is NO decoderSem next to bcryptSem/zipSem:
// a 1 Gbit/s NIC delivers ~0.125 GB/s, so even after allowing an order of
// magnitude for the 1 to 2 vCPU boxes this actually ships to, decode still
// runs 10 to 100 times faster than bytes can arrive. Concurrent uploads contend for
// bandwidth and disk long before CPU, and the parallel case shows no
// contention to cap anyway (the sync.Pool already bounds allocation, and each
// decoder is WithDecoderConcurrency(1), so N uploads cost N cores at worst).
// Re-run this before adding a cap: the reason to add one would be numbers
// that stopped looking like these, not a hunch.
func BenchmarkUploadDecode(b *testing.B) {
	cases := []struct {
		name         string
		size         int
		compressible bool
	}{
		{"text/8MiB", 8 << 20, true},
		{"incompressible/8MiB", 8 << 20, false},
		{"text/64KiB", 64 << 10, true},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			raw := benchPayload(b, tc.size, tc.compressible)
			enc := zstdEncode(b, raw)
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zr := zstdDecoders.Get().(*zstd.Decoder)
				src := &sourceBody{r: bytes.NewReader(enc)}
				if err := zr.Reset(src); err != nil {
					b.Fatal(err)
				}
				n, err := io.Copy(io.Discard, requestBody{r: zr, src: src, zstd: true})
				if err != nil {
					b.Fatal(err)
				}
				if n != int64(len(raw)) {
					b.Fatalf("decoded %d bytes, want %d", n, len(raw))
				}
				zr.Reset(nil)
				zstdDecoders.Put(zr)
			}
		})
	}
}

// BenchmarkUploadDecodeParallel is the question the cap would answer: does
// throughput hold up when several uploads decode at once? Run with -cpu to
// vary the contention.
func BenchmarkUploadDecodeParallel(b *testing.B) {
	raw := benchPayload(b, 8<<20, true)
	enc := zstdEncode(b, raw)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			zr := zstdDecoders.Get().(*zstd.Decoder)
			src := &sourceBody{r: bytes.NewReader(enc)}
			if err := zr.Reset(src); err != nil {
				b.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, requestBody{r: zr, src: src, zstd: true}); err != nil {
				b.Fatal(err)
			}
			zr.Reset(nil)
			zstdDecoders.Put(zr)
		}
	})
}
