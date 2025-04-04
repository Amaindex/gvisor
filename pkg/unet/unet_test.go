// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package unet

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

func randomFilename() (string, error) {
	// Return a randomly generated file in the test dir.
	f, err := os.CreateTemp("", "unet-test")
	if err != nil {
		return "", err
	}
	file := f.Name()
	os.Remove(file)
	f.Close()

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// NOTE(b/26918832): We try to use relative path if possible. This is
	// to help conforming to the unix path length limit.
	if rel, err := filepath.Rel(cwd, file); err == nil {
		return rel, nil
	}

	return file, nil
}

func TestConnectFailure(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	if _, err := Connect(name, false); err == nil {
		t.Fatalf("Connect was successful, expected err")
	}
}

func TestBindFailure(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	ss, err := BindAndListen(name, false)
	if err != nil {
		t.Fatalf("First bind failed, got err %v expected nil", err)
	}
	defer ss.Close()

	if _, err = BindAndListen(name, false); err == nil {
		t.Fatalf("Second bind succeeded, expected non-nil err")
	}
}

func TestMultipleAccept(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	ss, err := BindAndListen(name, false)
	if err != nil {
		t.Fatalf("First bind failed, got err %v expected nil", err)
	}
	defer ss.Close()

	// Connect backlog times asynchronously.
	var wg sync.WaitGroup
	defer wg.Wait()
	for i := 0; i < backlog; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Connect(name, false)
			if err != nil {
				t.Errorf("Connect failed, got err %v expected nil", err)
				return
			}
			s.Close()
		}()
	}

	// Accept backlog times.
	for i := 0; i < backlog; i++ {
		s, err := ss.Accept()
		if err != nil {
			t.Errorf("Accept failed, got err %v expected nil", err)
			continue
		}
		s.Close()
	}
}

func TestServerClose(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	ss, err := BindAndListen(name, false)
	if err != nil {
		t.Fatalf("First bind failed, got err %v expected nil", err)
	}

	// Make sure the first close succeeds.
	if err := ss.Close(); err != nil {
		t.Fatalf("First close failed, got err %v expected nil", err)
	}

	// The second one should fail.
	if err := ss.Close(); err == nil {
		t.Fatalf("Second close succeeded, expected non-nil err")
	}
}

func socketPair(t *testing.T, packet bool) (*Socket, *Socket) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	// Bind a server.
	ss, err := BindAndListen(name, packet)
	if err != nil {
		t.Fatalf("Error binding, got %v expected nil", err)
	}
	defer ss.Close()

	// Accept a client.
	acceptSocket := make(chan *Socket)
	acceptErr := make(chan error)
	go func() {
		server, err := ss.Accept()
		if err != nil {
			acceptErr <- err
		}
		acceptSocket <- server
	}()

	// Connect the client.
	client, err := Connect(name, packet)
	if err != nil {
		t.Fatalf("Error connecting, got %v expected nil", err)
	}

	// Grab the server handle.
	select {
	case server := <-acceptSocket:
		return server, client
	case err := <-acceptErr:
		t.Fatalf("Accept error: %v", err)
	}
	panic("unreachable")
}

func TestSendRecv(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Write on the client.
	w := client.Writer(true)
	if n, err := w.WriteVec([][]byte{{'a'}}); n != 1 || err != nil {
		t.Fatalf("For client write, got n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Read on the server.
	b := [][]byte{{'b'}}
	r := server.Reader(true)
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("For server read, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
	if b[0][0] != 'a' {
		t.Fatalf("Got bad read data, got %c, expected a", b[0][0])
	}
}

// TestSymmetric exists to assert that the two sockets received from socketPair
// are interchangeable. They should be, this just provides a basic sanity check
// by running TestSendRecv "backwards".
func TestSymmetric(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Write on the server.
	w := server.Writer(true)
	if n, err := w.WriteVec([][]byte{{'a'}}); n != 1 || err != nil {
		t.Fatalf("For server write, got n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Read on the client.
	b := [][]byte{{'b'}}
	r := client.Reader(true)
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("For client read, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
	if b[0][0] != 'a' {
		t.Fatalf("Got bad read data, got %c, expected a", b[0][0])
	}
}

func TestPacket(t *testing.T) {
	server, client := socketPair(t, true)
	defer server.Close()
	defer client.Close()

	// Write on the client.
	w := client.Writer(true)
	if n, err := w.WriteVec([][]byte{{'a'}}); n != 1 || err != nil {
		t.Fatalf("For client write, got n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Write on the client again.
	w = client.Writer(true)
	if n, err := w.WriteVec([][]byte{{'a'}}); n != 1 || err != nil {
		t.Fatalf("For client write, got n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Read on the server.
	//
	// This should only get back a single byte, despite the buffer
	// being size two. This is because it's a _packet_ buffer.
	b := [][]byte{{'b', 'b'}}
	r := server.Reader(true)
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("For server read, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
	if b[0][0] != 'a' {
		t.Fatalf("Got bad read data, got %c, expected a", b[0][0])
	}

	// Do it again.
	r = server.Reader(true)
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("For server read, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
	if b[0][0] != 'a' {
		t.Fatalf("Got bad read data, got %c, expected a", b[0][0])
	}
}

func TestClose(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()

	// Make sure the first close succeeds.
	if err := client.Close(); err != nil {
		t.Fatalf("First close failed, got err %v expected nil", err)
	}

	// The second one should fail.
	if err := client.Close(); err == nil {
		t.Fatalf("Second close succeeded, expected non-nil err")
	}
}

func TestNonBlockingSend(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Try up to 1000 writes, of 1000 bytes.
	blockCount := 0
	for i := 0; i < 1000; i++ {
		w := client.Writer(false)
		if n, err := w.WriteVec([][]byte{make([]byte, 1000)}); n != 1000 || err != nil {
			if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
				// We're good. That's what we wanted.
				blockCount++
			} else {
				t.Fatalf("For client write, got n=%d err=%v, expected n=1000 err=nil", n, err)
			}
		}
	}

	if blockCount == 1000 {
		// Shouldn't have _always_ blocked.
		t.Fatalf("Socket always blocked!")
	} else if blockCount == 0 {
		// Should have started blocking eventually.
		t.Fatalf("Socket never blocked!")
	}
}

func TestNonBlockingRecv(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	b := [][]byte{{'b'}}
	r := client.Reader(false)

	// Expected to block immediately.
	_, err := r.ReadVec(b)
	if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatalf("Read didn't block, got err %v expected blocking err", err)
	}

	// Put some data in the pipe.
	w := server.Writer(false)
	if n, err := w.WriteVec(b); n != 1 || err != nil {
		t.Fatalf("Write failed with n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Expect it not to block.
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("Read failed with n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Expect it to return a block error again.
	r = client.Reader(false)
	_, err = r.ReadVec(b)
	if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatalf("Read didn't block, got err %v expected blocking err", err)
	}
}

func TestRecvVectors(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Write on the client.
	w := client.Writer(true)
	if n, err := w.WriteVec([][]byte{{'a', 'b'}}); n != 2 || err != nil {
		t.Fatalf("For client write, got n=%d err=%v, expected n=2 err=nil", n, err)
	}

	// Read on the server.
	b := [][]byte{{'c'}, {'c'}}
	r := server.Reader(true)
	if n, err := r.ReadVec(b); n != 2 || err != nil {
		t.Fatalf("For server read, got n=%d err=%v, expected n=2 err=nil", n, err)
	}
	if b[0][0] != 'a' || b[1][0] != 'b' {
		t.Fatalf("Got bad read data, got %c,%c, expected a,b", b[0][0], b[1][0])
	}
}

func TestSendVectors(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Write on the client.
	w := client.Writer(true)
	if n, err := w.WriteVec([][]byte{{'a'}, {'b'}}); n != 2 || err != nil {
		t.Fatalf("For client write, got n=%d err=%v, expected n=2 err=nil", n, err)
	}

	// Read on the server.
	b := [][]byte{{'c', 'c'}}
	r := server.Reader(true)
	if n, err := r.ReadVec(b); n != 2 || err != nil {
		t.Fatalf("For server read, got n=%d err=%v, expected n=2 err=nil", n, err)
	}
	if b[0][0] != 'a' || b[0][1] != 'b' {
		t.Fatalf("Got bad read data, got %c,%c, expected a,b", b[0][0], b[0][1])
	}
}

func TestSendFDsNotEnabled(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Write on the server.
	w := server.Writer(true)
	w.PackFDs(0, 1, 2)
	if n, err := w.WriteVec([][]byte{{'a'}}); n != 1 || err != nil {
		t.Fatalf("For server write, got n=%d err=%v, expected n=1 err=nil", n, err)
	}

	// Read on the client, without enabling FDs.
	b := [][]byte{{'b'}}
	r := client.Reader(true)
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("For client read, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
	if b[0][0] != 'a' {
		t.Fatalf("Got bad read data, got %c, expected a", b[0][0])
	}

	// Make sure the FDs are not received.
	fds, err := r.ExtractFDs()
	if len(fds) != 0 || err != nil {
		t.Fatalf("Got fds=%v err=%v, expected len(fds)=0 err=nil", fds, err)
	}
}

func sendFDs(t *testing.T, s *Socket, fds []int) {
	w := s.Writer(true)
	w.PackFDs(fds...)
	if n, err := w.WriteVec([][]byte{{'a'}}); n != 1 || err != nil {
		t.Fatalf("For write, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
}

func recvFDs(t *testing.T, s *Socket, enableSize int, origFDs []int) {
	expected := len(origFDs)

	// Count the number of FDs.
	preEntries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Can't readdir, got err %v expected nil", err)
	}

	// Read on the client.
	b := [][]byte{{'b'}}
	r := s.Reader(true)
	if enableSize >= 0 {
		r.EnableFDs(enableSize)
	}
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		t.Fatalf("For client read, got n=%d err=%v, expected n=1 err=nil", n, err)
	}
	if b[0][0] != 'a' {
		t.Fatalf("Got bad read data, got %c, expected a", b[0][0])
	}

	// Count the new number of FDs.
	postEntries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Can't readdir, got err %v expected nil", err)
	}
	if len(preEntries)+expected != len(postEntries) {
		t.Errorf("Process fd count isn't right, expected %d got %d", len(preEntries)+expected, len(postEntries))
	}

	// Make sure the FDs are there.
	fds, err := r.ExtractFDs()
	if len(fds) != expected || err != nil {
		t.Fatalf("Got fds=%v err=%v, expected len(fds)=%d err=nil", fds, err, expected)
	}

	// Make sure they are different from the originals.
	for i := 0; i < len(fds); i++ {
		if fds[i] == origFDs[i] {
			t.Errorf("Got original fd for index %d, expected different", i)
		}
	}

	// Make sure they can be accessed as expected.
	for i := 0; i < len(fds); i++ {
		var st unix.Stat_t
		if err := unix.Fstat(fds[i], &st); err != nil {
			t.Errorf("fds[%d] can't be stated, got err %v expected nil", i, err)
		}
	}

	// Close them off.
	r.CloseFDs()

	// Make sure the count is back to normal.
	finalEntries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Can't readdir, got err %v expected nil", err)
	}
	if len(finalEntries) != len(preEntries) {
		t.Errorf("Process fd count isn't right, expected %d got %d", len(preEntries), len(finalEntries))
	}
}

func TestFDsSingle(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	sendFDs(t, server, []int{0})
	recvFDs(t, client, 1, []int{0})
}

func TestFDsMultiple(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	// Basic case, multiple FDs.
	sendFDs(t, server, []int{0, 1, 2})
	recvFDs(t, client, 3, []int{0, 1, 2})
}

// See TestSymmetric above.
func TestFDsSymmetric(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	sendFDs(t, server, []int{0, 1, 2})
	recvFDs(t, client, 3, []int{0, 1, 2})
}

func TestFDsReceiveLargeBuffer(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	sendFDs(t, server, []int{0})
	recvFDs(t, client, 3, []int{0})
}

func TestFDsReceiveSmallBuffer(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	sendFDs(t, server, []int{0, 1, 2})

	// Per the spec, we may still receive more than the buffer. In fact,
	// it'll be rounded up and we can receive two with a size one buffer.
	recvFDs(t, client, 1, []int{0, 1})
}

func TestFDsReceiveNotEnabled(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	sendFDs(t, server, []int{0})
	recvFDs(t, client, -1, []int{})
}

func TestFDsReceiveSizeZero(t *testing.T) {
	server, client := socketPair(t, false)
	defer server.Close()
	defer client.Close()

	sendFDs(t, server, []int{0})
	recvFDs(t, client, 0, []int{})
}

func newClosedSocket() (*Socket, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	s, err := NewSocket(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return s, s.Close()
}

func TestAcceptClosed(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	ss, err := BindAndListen(name, false)
	if err != nil {
		t.Fatalf("Bind failed, got err %v expected nil", err)
	}

	if err := ss.Close(); err != nil {
		t.Fatalf("Close failed, got err %v expected nil", err)
	}

	if _, err := ss.Accept(); err == nil {
		t.Errorf("Accept on closed SocketServer, got err %v, want != nil", err)
	}
}

func TestCloseAfterAcceptStart(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	ss, err := BindAndListen(name, false)
	if err != nil {
		t.Fatalf("Bind failed, got err %v expected nil", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		if err := ss.Close(); err != nil {
			t.Errorf("Close failed, got err %v expected nil", err)
		}
	}()

	if _, err := ss.Accept(); err == nil {
		t.Errorf("Accept on closed SocketServer, got err %v, want != nil", err)
	}

	wg.Wait()
}

func TestReleaseAfterAcceptStart(t *testing.T) {
	name, err := randomFilename()
	if err != nil {
		t.Fatalf("Unable to generate file, got err %v expected nil", err)
	}

	ss, err := BindAndListen(name, false)
	if err != nil {
		t.Fatalf("Bind failed, got err %v expected nil", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		fd, err := ss.Release()
		if err != nil {
			t.Errorf("Release failed, got err %v expected nil", err)
		}
		unix.Close(fd)
	}()

	if _, err := ss.Accept(); err == nil {
		t.Errorf("Accept on closed SocketServer, got err %v, want != nil", err)
	}

	wg.Wait()
}

func TestControlMessage(t *testing.T) {
	for i := 0; i <= 10; i++ {
		var want []int
		for j := 0; j < i; j++ {
			want = append(want, i+j+1)
		}

		var cm ControlMessage
		cm.EnableFDs(i)
		cm.PackFDs(want...)
		got, err := cm.ExtractFDs()
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("cm.ExtractFDs() = %v, %v, want = %v, %v", got, err, want, nil)
		}
	}
}

func benchmarkSendRecv(b *testing.B, packet bool) {
	server, client, err := SocketPair(packet)
	if err != nil {
		b.Fatalf("SocketPair: got %v, wanted nil", err)
	}
	defer server.Close()
	defer client.Close()
	go func() {
		buf := make([]byte, 1)
		for i := 0; i < b.N; i++ {
			n, err := server.Read(buf)
			if n != 1 || err != nil {
				b.Errorf("server.Read: got (%d, %v), wanted (1, nil)", n, err)
				return
			}
			n, err = server.Write(buf)
			if n != 1 || err != nil {
				b.Errorf("server.Write: got (%d, %v), wanted (1, nil)", n, err)
				return
			}
		}
	}()
	buf := make([]byte, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := client.Write(buf)
		if n != 1 || err != nil {
			b.Fatalf("client.Write: got (%d, %v), wanted (1, nil)", n, err)
		}
		n, err = client.Read(buf)
		if n != 1 || err != nil {
			b.Fatalf("client.Read: got (%d, %v), wanted (1, nil)", n, err)
		}
	}
}

func BenchmarkSendRecvStream(b *testing.B) {
	benchmarkSendRecv(b, false)
}

func BenchmarkSendRecvPacket(b *testing.B) {
	benchmarkSendRecv(b, true)
}
