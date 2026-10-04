package sshclient

import "sync"

// SafeBuffer is an append-only byte buffer that is safe for concurrent use.
// The SSH library writes remote output into it from its own goroutine while the
// expect loop reads from another; a plain bytes.Buffer would be a data race.
// Every Write also signals Notify so readers can sleep instead of polling.
type SafeBuffer struct {
	mu     sync.Mutex
	buf    []byte
	notify chan struct{}
}

// NewSafeBuffer returns an empty buffer ready for use.
func NewSafeBuffer() *SafeBuffer {
	return &SafeBuffer{notify: make(chan struct{}, 1)}
}

// Write appends p and wakes a waiting reader.
func (b *SafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.buf = append(b.buf, p...)
	b.mu.Unlock()
	select {
	case b.notify <- struct{}{}:
	default: // a wake-up is already pending
	}
	return len(p), nil
}

// Notify returns a channel that receives a value after new data was written.
// Wake-ups coalesce: always re-read the buffer after receiving.
func (b *SafeBuffer) Notify() <-chan struct{} { return b.notify }

// Len returns the number of bytes written so far.
func (b *SafeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}

// Since returns a copy of the bytes from offset off to the end.
func (b *SafeBuffer) Since(off int) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if off < 0 {
		off = 0
	}
	if off >= len(b.buf) {
		return nil
	}
	out := make([]byte, len(b.buf)-off)
	copy(out, b.buf[off:])
	return out
}

// String returns everything written so far.
func (b *SafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
