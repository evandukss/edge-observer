//go:build attach

package ebpf_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"debug/elf"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

const certificationActor = `
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
static SSL_CTX *ctx;
static SSL *ssl[32];
static int fd[32], serial[32], connect_calls[32], port, repetitions;
static void connect_one(int i, int handshake) {
 fd[i]=socket(AF_INET,SOCK_STREAM,0);
 struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};
 inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
 if(connect(fd[i],(void*)&a,sizeof(a)))exit(21);
 if(!ssl[i])ssl[i]=SSL_new(ctx);
 if(!ssl[i])exit(22);
 SSL_set_fd(ssl[i],fd[i]);
 if(handshake){connect_calls[i]++;if(SSL_connect(ssl[i])!=1)exit(23);}
 else SSL_set_connect_state(ssl[i]);
}
static void open_one(int i) {connect_one(i,1);}
static void write_one(int i) {
 char b[512];memset(b,'#',sizeof(b));
 int n=snprintf(b,sizeof(b),"handle=%02d call=%06d",i,++serial[i]);
 b[n]='#';
 if(SSL_write(ssl[i],b,sizeof(b))!=sizeof(b))exit(24);
}
static int read_result, read_byte;
static void write_ex_one(int i) {
 char b[512];memset(b,'#',sizeof(b));int n=snprintf(b,sizeof(b),"handle=%02d call=%06d",i,++serial[i]);b[n]='#';
 size_t count=0;if(SSL_write_ex(ssl[i],b,sizeof(b),&count)!=1||count!=sizeof(b))exit(29);
}
static void *read_once(void *p) { (void)p; char b; read_result=SSL_read(ssl[0],&b,1);read_byte=(unsigned char)b;return NULL;}
static void *burst(void *p) {int i=(int)(long)p;for(int n=0;n<repetitions;n++)write_one(i);return NULL;}
int main(int argc,char **argv) {
 (void)argc;signal(SIGPIPE,SIG_IGN);port=atoi(argv[1]);
 ctx=SSL_CTX_new(TLS_client_method());SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
 puts("ready");fflush(stdout);
 char line[128],op;int i,n;
 while(fgets(line,sizeof(line),stdin)) {
 i=n=0;sscanf(line,"%c %d %d",&op,&i,&n);
 if(op=='K'){SSL_CTX_set_options(ctx,SSL_OP_ENABLE_KTLS);puts("K ok");}
 if(op=='Q')printf("Q %ld\n",BIO_get_ktls_send(SSL_get_wbio(ssl[i])));
 if(op=='S'){char path[]="/tmp/transfer-XXXXXX",b[512];memset(b,'#',sizeof(b));int n=snprintf(b,sizeof(b),"handle=%02d call=%06d",i,++serial[i]);b[n]='#';int file=mkstemp(path);if(file<0)exit(30);unlink(path);if(write(file,b,sizeof(b))!=sizeof(b))exit(31);long result=SSL_sendfile(ssl[i],file,0,sizeof(b),0);close(file);printf("S %ld\n",result);}
 if(op=='L'){if(ssl[i])exit(32);connect_one(i,0);printf("L %d %llu %d %d\n",i,(unsigned long long)ssl[i],connect_calls[i],SSL_is_init_finished(ssl[i]));}
 if(op=='H')printf("H %d %d\n",connect_calls[i],SSL_is_init_finished(ssl[i]));
 if(op=='I'){char b[512];int count=SSL_read(ssl[i],b,sizeof(b));if(count!=sizeof(b))exit(33);for(int j=0;j<count;j++)if(b[j]!='r')exit(34);puts("I ok");}
 if(op=='N'){open_one(i);printf("N %d %llu\n",i,(unsigned long long)ssl[i]);}
 if(op=='W'){for(int j=0;j<n;j++)write_one(i);puts("W ok");}
 if(op=='B'){pthread_t th[32];repetitions=n;for(int j=0;j<i;j++)if(pthread_create(&th[j],NULL,burst,(void*)(long)j))exit(25);for(int j=0;j<i;j++)pthread_join(th[j],NULL);puts("B ok");}
 if(op=='E'){write_ex_one(i);puts("E ok");}
 if(op=='Z'){char b;int result=SSL_read(ssl[i],&b,0);printf("Z %d\n",result);}
 if(op=='R'){pthread_t th;if(pthread_create(&th,NULL,read_once,NULL))exit(28);pthread_join(th,NULL);printf("R %d %d\n",read_result,read_byte);}
 if(op=='V'){char b;size_t count=0;int result=SSL_read_ex(ssl[i],&b,1,&count);printf("V %d %zu %d\n",result,count,(unsigned char)b);}
 if(op=='F'){SSL_free(ssl[i]);ssl[i]=NULL;close(fd[i]);puts("F ok");}
 if(op=='U'){unsigned long long old;sscanf(line,"U %d %llu",&i,&old);int tries;for(tries=0;tries<1000;tries++){ssl[i]=SSL_new(ctx);if((unsigned long long)ssl[i]==old)break;SSL_free(ssl[i]);}if(tries==1000)exit(26);open_one(i);printf("U %d %llu %d\n",i,(unsigned long long)ssl[i],tries+1);}
 if(op=='C'){SSL_set_shutdown(ssl[i],SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);if(SSL_clear(ssl[i])!=1)exit(27);close(fd[i]);open_one(i);printf("C %d %llu\n",i,(unsigned long long)ssl[i]);}
 fflush(stdout);
 }
 return 0;
}
`

type certificationRun struct {
	session  *ebpf.Session
	input    io.WriteCloser
	output   *bufio.Reader
	peers    chan *tls.Conn
	received chan []byte
	events   []ebpf.Event
}

func certificationFixture(t *testing.T, configure func(*ebpf.Options)) *certificationRun {
	t.Helper()
	return certificationFixtureWithGreeting(t, configure, nil)
}

func certificationFixtureWithGreeting(t *testing.T, configure func(*ebpf.Options), greeting []byte) *certificationRun {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cert.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates})
	if err != nil {
		t.Fatalf("wiring, not the property: TLS listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	r := &certificationRun{peers: make(chan *tls.Conn, 32), received: make(chan []byte, 4096)}
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func(c *tls.Conn) {
				defer func() { _ = c.Close() }()
				if c.Handshake() != nil {
					return
				}
				if len(greeting) != 0 {
					if _, err := c.Write(greeting); err != nil {
						return
					}
				}
				r.peers <- c
				for {
					b := make([]byte, 512)
					if _, e := io.ReadFull(c, b); e != nil {
						return
					}
					r.received <- b
				}
			}(c.(*tls.Conn))
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	dir := t.TempDir()
	source := filepath.Join(dir, "actor.c")
	binary := filepath.Join(dir, "actor")
	if err := os.WriteFile(source, []byte(certificationActor), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-pthread", "-o", binary, source, "-lssl", "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: actor compile: %v: %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary, port)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	r.input = input
	r.output = bufio.NewReader(output)
	if line, err := r.output.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("wiring, not the property: actor startup %q: %v", line, err)
	}
	table, err := process.Read("/proc")
	if err != nil {
		t.Fatal(err)
	}
	who, ok := table.Lookup(int32(cmd.Process.Pid))
	if !ok {
		t.Fatal("wiring, not the property: actor process absent")
	}
	support := openssl.New().Inspect(who)
	if !support.Supported {
		t.Fatalf("wiring, not the property: actor support: %s", support.Reason)
	}
	points, discarded := ebpf.PointsFrom(support.Probes, openssl.New().Runtime)
	if len(points) == 0 || len(discarded) != 0 {
		t.Fatalf("wiring, not the property: resolved points=%d discarded=%v", len(points), discarded)
	}
	options := ebpf.Options{Program: bpf.Full(), Points: points, Admit: []admission.Selection{{Instance: who.Instance(), Kind: admission.ByTarget, Provenance: admission.Provenance{Target: who.Executable, Number: 1}, Mode: admission.ModeFollow, ObserverPID: who.PID}}, Staging: 1}
	if configure != nil {
		configure(&options)
	}
	r.session, err = ebpf.Attach(options)
	if err != nil {
		t.Fatalf("wiring, not the property: attach: %v", err)
	}
	t.Cleanup(func() { _ = r.session.Close() })
	return r
}

func (r *certificationRun) command(t *testing.T, command string) string {
	t.Helper()
	if _, err := fmt.Fprintln(r.input, command); err != nil {
		t.Fatal(err)
	}
	line, err := r.output.ReadString('\n')
	if err != nil {
		t.Fatalf("wiring, not the property: command %q: %q: %v", command, line, err)
	}
	return strings.TrimSpace(line)
}
func (r *certificationRun) expect(t *testing.T, command, want string) {
	t.Helper()
	if got := r.command(t, command); got != want {
		t.Fatalf("wiring, not the property: %q returned %q, want %q", command, got, want)
	}
}
func (r *certificationRun) peer(t *testing.T) *tls.Conn {
	t.Helper()
	select {
	case c := <-r.peers:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("wiring, not the property: real TLS handshake absent")
		return nil
	}
}
func (r *certificationRun) open(t *testing.T, i int) (uint64, *tls.Conn) {
	t.Helper()
	line := r.command(t, fmt.Sprintf("N %d", i))
	var index int
	var address uint64
	if _, err := fmt.Sscanf(line, "N %d %d", &index, &address); err != nil || index != i || address == 0 {
		t.Fatalf("wiring, not the property: open %q", line)
	}
	return address, r.peer(t)
}
func (r *certificationRun) next(t *testing.T, d fragment.Direction) ebpf.Event {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case e := <-r.session.Events():
			r.events = append(r.events, e)
			if e.Kind == ebpf.Transfer && e.Direction == d {
				return e
			}
		case <-deadline.C:
			t.Fatalf("wiring, not the property: no %s transfer reached consumer", d)
			return ebpf.Event{}
		}
	}
}
func (r *certificationRun) bytes(t *testing.T, n int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, n)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for len(out) < n {
		select {
		case b := <-r.received:
			out = append(out, b)
		case <-deadline.C:
			t.Fatalf("wiring, not the property: peer read %d of %d payloads", len(out), n)
		}
	}
	return out
}
func certificationPayload(i, n int) []byte {
	b := bytes.Repeat([]byte{'#'}, 512)
	copy(b, fmt.Sprintf("handle=%02d call=%06d", i, n))
	return b
}
func certificationPayloadID(t *testing.T, b []byte) (int, int) {
	t.Helper()
	var i, n int
	if len(b) != 512 {
		t.Fatalf("wiring, not the property: actor payload size=%d", len(b))
	}
	if _, err := fmt.Sscanf(string(b[:21]), "handle=%02d call=%06d", &i, &n); err != nil {
		t.Fatalf("wiring, not the property: payload identity %q: %v", b[:21], err)
	}
	return i, n
}
func (r *certificationRun) stop(t *testing.T) {
	t.Helper()
	w, err := r.session.StopProducing()
	if err != nil || !w.Complete {
		t.Fatalf("wiring, not the property: stop %+v: %v", w, err)
	}
	done := make(chan error, 1)
	go func() {
		d, err := r.session.Drain(3 * time.Second)
		if err == nil && !d.Complete {
			err = fmt.Errorf("incomplete drain: %+v", d)
		}
		done <- err
	}()
	for {
		select {
		case e := <-r.session.Events():
			r.events = append(r.events, e)
		case err := <-done:
			if err != nil {
				t.Fatalf("wiring, not the property: drain: %v", err)
			}
			for {
				select {
				case e := <-r.session.Events():
					r.events = append(r.events, e)
				default:
					return
				}
			}
		}
	}
}
func certificationHandle(e ebpf.Event) probe.Handle {
	return probe.Handle{Instance: admission.Key{Namespace: e.Namespace, PID: e.NamespacePID, Generation: e.Generation}, Endpoint: e.SSL}
}

func TestProducerEntryNumberSurvivesMissingReturn(t *testing.T) {
	r := certificationFixture(t, nil)
	_, peer := r.open(t, 0)
	r.expect(t, "W 0 1", "W ok")
	sent := r.next(t, fragment.Sent)
	wire := r.bytes(t, 1)
	if sent.Length != 512 || !bytes.Equal(wire[0], certificationPayload(0, 1)) {
		t.Fatal("wiring, not the property: initial write did not reach producer and peer")
	}
	removed, err := ebpf.IndependentRemoveReturn(r.session, "SSL_read")
	if err != nil || removed != 1 {
		t.Fatalf("wiring, not the property: removed return links=%d: %v", removed, err)
	}
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	r.expect(t, "R 0", "R 1 120")
	if _, err := peer.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	r.expect(t, "V 0", "V 1 1 121")
	e := r.next(t, fragment.Received)
	if e.Length != 1 || !bytes.Equal(e.Payload, []byte("y")) {
		t.Fatalf("wiring, not the property: later read did not reach producer: %+v", e)
	}
	r.stop(t)
	t.Logf("PRECONDITIONS removed_returns=%d successful_reads=2 later_read_events=1 observed_before_stop=1", removed)
	if e.Sequence.Number != 2 || e.Sequence.Occupancy != sent.Sequence.Occupancy || !e.Sequence.Born {
		t.Errorf("missing return lost its entry number or identity: %+v sent=%+v", e.Sequence, sent.Sequence)
	}
	reads := 0
	for _, event := range r.events {
		if event.Kind == ebpf.Transfer && event.Direction == fragment.Received {
			reads++
		}
	}
	if reads != 1 {
		t.Errorf("absent return produced %d read events, want 1", reads)
	}
	final, err := r.session.Settled(certificationHandle(e))
	if err != nil {
		t.Fatal(err)
	}
	if !final.Final.Known || final.Final.Received.Last != 2 || final.Final.Received.Dropped != 0 {
		t.Errorf("missing callback is not a reservation drop: %+v", final)
	}
}

func TestProducerZeroByteResolutionKeepsItsPlace(t *testing.T) {
	r := certificationFixture(t, nil)
	_, peer := r.open(t, 0)
	r.expect(t, "W 0 1", "W ok")
	sent := r.next(t, fragment.Sent)
	r.bytes(t, 1)
	// A queued record prevents SSL_read(size=0) from waiting for network input.
	if _, err := peer.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	r.expect(t, "Z 0", "Z 0")
	zero := r.next(t, fragment.Received)
	r.expect(t, "V 0", "V 1 1 122")
	data := r.next(t, fragment.Received)
	if data.Length != 1 || string(data.Payload) != "z" {
		t.Fatalf("wiring, not the property: actual read missing: %+v", data)
	}
	r.stop(t)
	t.Log("PRECONDITIONS zero_byte_calls=1 subsequent_successful_reads=1 observed_before_stop=1")
	if zero.Length != 0 || len(zero.Payload) != 0 || !zero.Measured || zero.Sequence.Number != 1 {
		t.Errorf("zero-byte call not explicitly resolved: %+v", zero)
	}
	if data.Sequence.Number != 2 || zero.Sequence.Occupancy != sent.Sequence.Occupancy || data.Sequence.Occupancy != sent.Sequence.Occupancy {
		t.Errorf("resolution shifted occupancy or numbering: zero=%+v data=%+v sent=%+v", zero.Sequence, data.Sequence, sent.Sequence)
	}
}

func TestProducerReservationLossIsPerOccupancy(t *testing.T) {
	for _, handles := range []int{1, 9} {
		t.Run(strconv.Itoa(handles), func(t *testing.T) {
			r := certificationFixture(t, func(o *ebpf.Options) { o.Resize = map[string]uint32{"events": 32768} })
			origins := make(map[int]ebpf.Event)
			for i := 0; i < handles; i++ {
				r.open(t, i)
				r.expect(t, fmt.Sprintf("W %d 1", i), "W ok")
				origins[i] = r.next(t, fragment.Sent)
				wire := r.bytes(t, 1)
				if !bytes.Equal(wire[0], certificationPayload(i, 1)) {
					t.Fatal("wiring, not the property: initial peer payload differs")
				}
			}
			// No consumer drains the one-entry staging queue while these threads write.
			r.expect(t, fmt.Sprintf("B %d 83", handles), "B ok")
			wire := r.bytes(t, handles*83)
			seen := make(map[[2]int]bool)
			for _, b := range wire {
				i, n := certificationPayloadID(t, b)
				if i < 0 || i >= handles || n < 2 || n > 84 || seen[[2]int{i, n}] || !bytes.Equal(b, certificationPayload(i, n)) {
					t.Fatal("wiring, not the property: peer burst population differs")
				}
				seen[[2]int{i, n}] = true
			}
			drops, err := r.session.Dropped()
			if err != nil {
				t.Fatal(err)
			}
			if drops == 0 {
				t.Fatalf("UNPROVED: attempts=%d reservation_failures=0", handles*83)
			}
			r.stop(t)
			t.Logf("PRECONDITIONS live_handles=%d completed_calls=%d peer_burst_payloads=%d reservation_failures=%d", handles, handles*84, len(wire), drops)
			delivered := make(map[int]map[uint64]bool)
			ids := make(map[uint64]bool)
			for i, e := range origins {
				delivered[i] = make(map[uint64]bool)
				if e.Sequence.Occupancy == 0 || ids[e.Sequence.Occupancy] || !e.Sequence.Born || e.Sequence.Number != 1 {
					t.Errorf("distinct born origins missing: %+v", e.Sequence)
				}
				ids[e.Sequence.Occupancy] = true
			}
			for _, e := range r.events {
				if e.Kind != ebpf.Transfer || e.Direction != fragment.Sent {
					continue
				}
				i, n := certificationPayloadID(t, e.Payload)
				if i < 0 || i >= handles {
					t.Fatal("wiring, not the property: unknown actor payload")
				}
				if !bytes.Equal(e.Payload, certificationPayload(i, n)) || e.Sequence.Occupancy != origins[i].Sequence.Occupancy || e.Sequence.Number != uint64(n) {
					t.Errorf("producer sequence disagrees with independent payload identity: handle=%d call=%d sequence=%+v", i, n, e.Sequence)
				}
				if delivered[i][e.Sequence.Number] {
					t.Errorf("duplicate operation handle=%d number=%d", i, e.Sequence.Number)
				}
				delivered[i][e.Sequence.Number] = true
			}
			total := uint64(0)
			for i, e := range origins {
				s, err := r.session.Settled(certificationHandle(e))
				if err != nil {
					t.Fatal(err)
				}
				missing := uint64(84 - len(delivered[i]))
				t.Logf("TRACE handle=%d occupancy=%d received=%d missing=%d terminal=%+v", i, e.Sequence.Occupancy, len(delivered[i]), missing, s.Final.Sent)
				if !s.Final.Known || s.Occupancy != e.Sequence.Occupancy || s.Final.Sent.Last != 84 || s.Final.Sent.Dropped != missing || s.Final.Received.Last != 0 || s.Final.Received.Dropped != 0 {
					t.Errorf("reservation loss not attributable to exactly its numbered operations: handle=%d settlement=%+v missing=%d", i, s, missing)
				}
				total += s.Final.Sent.Dropped
			}
			if total != uint64(drops) {
				t.Errorf("per-occupancy reservation loss=%d aggregate=%d", total, drops)
			}
		})
	}
}

func TestProducerLifecycleCoveragePreventsAddressAlias(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(strconv.FormatBool(refused), func(t *testing.T) {
			r := certificationFixture(t, func(o *ebpf.Options) {
				if refused {
					o.FailEntry = []string{"SSL_new", "SSL_free"}
				}
			})
			address, _ := r.open(t, 0)
			r.expect(t, "W 0 1", "W ok")
			first := r.next(t, fragment.Sent)
			r.bytes(t, 1)
			r.expect(t, "F 0", "F ok")
			line := r.command(t, fmt.Sprintf("U 0 %d", address))
			var index, attempts int
			var reused uint64
			if _, err := fmt.Sscanf(line, "U %d %d %d", &index, &reused, &attempts); err != nil || index != 0 || reused != address || attempts < 1 {
				t.Fatalf("wiring, not the property: exact address reuse absent: %q", line)
			}
			r.peer(t)
			r.expect(t, "W 0 1", "W ok")
			second := r.next(t, fragment.Sent)
			wire := r.bytes(t, 1)
			if first.Length != 512 || second.Length != 512 || !bytes.Equal(wire[0], certificationPayload(0, 2)) {
				t.Fatal("wiring, not the property: two real connections did not move both payloads")
			}
			r.stop(t)
			t.Logf("PRECONDITIONS refused_lifecycle=%t real_TLS_connections=2 exact_address_reuses=1 allocation_attempts=%d before=%+v after=%+v", refused, attempts, first.Sequence, second.Sequence)
			if refused {
				for _, symbol := range []string{"SSL_new", "SSL_free"} {
					if !slices.Contains(r.session.Unprobed(), symbol) {
						t.Errorf("present failed lifecycle probe absent from coverage: %s", symbol)
					}
				}
				if first.Sequence.Occupancy != 0 || second.Sequence.Occupancy != 0 || first.Sequence.Born || second.Sequence.Born {
					t.Errorf("uncovered lifecycle assigned qualified identities: first=%+v second=%+v", first.Sequence, second.Sequence)
				}
			} else if first.Sequence.Occupancy == 0 || second.Sequence.Occupancy == 0 || first.Sequence.Occupancy == second.Sequence.Occupancy || !first.Sequence.Born || !second.Sequence.Born || first.Sequence.Number != 1 || second.Sequence.Number != 1 {
				t.Errorf("fully placed lifecycle did not separate reused address: first=%+v second=%+v", first.Sequence, second.Sequence)
			}
		})
	}
}

func TestProducerClearStartsNewOccupancy(t *testing.T) {
	r := certificationFixture(t, nil)
	address, _ := r.open(t, 0)
	r.expect(t, "W 0 1", "W ok")
	first := r.next(t, fragment.Sent)
	r.bytes(t, 1)
	before := append([]byte(nil), first.Payload...)
	line := r.command(t, "C 0")
	var index int
	var recycled uint64
	if _, err := fmt.Sscanf(line, "C %d %d", &index, &recycled); err != nil || index != 0 || recycled != address {
		t.Fatalf("wiring, not the property: external clear did not retain address: %q", line)
	}
	r.peer(t)
	r.expect(t, "W 0 1", "W ok")
	second := r.next(t, fragment.Sent)
	wire := r.bytes(t, 1)
	if first.Length != 512 || second.Length != 512 || !bytes.Equal(wire[0], certificationPayload(0, 2)) {
		t.Fatal("wiring, not the property: both real TLS connections must move bytes")
	}
	r.stop(t)
	t.Logf("PRECONDITIONS external_clear_calls=1 real_TLS_connections=2 same_address=1 ordinary_initialisations=1 first=%+v second=%+v", first.Sequence, second.Sequence)
	if first.Sequence.Occupancy == 0 || !first.Sequence.Born || first.Sequence.Number != 1 {
		t.Errorf("ordinary initialization lost its qualified origin: %+v", first.Sequence)
	}
	if second.Sequence.Occupancy == 0 || second.Sequence.Occupancy == first.Sequence.Occupancy || second.Sequence.Number != 1 {
		t.Errorf("external clear continued the old occupancy: first=%+v second=%+v", first.Sequence, second.Sequence)
	}
	if !bytes.Equal(before, certificationPayload(0, 1)) || !bytes.Equal(first.Payload, before) || !bytes.Equal(second.Payload, certificationPayload(0, 2)) {
		t.Error("a later recycled handle changed or misattributed an earlier captured payload")
	}
}

// This case does not count internal SSL_clear calls: the product exposes no count.
// It can pass if the library no longer calls SSL_clear during the handshake.
func TestProducerImplicitWriteHandshakePreservesOccupancy(t *testing.T) {
	certificationImplicitHandshake(t, false)
}

// This case does not count internal SSL_clear calls: the product exposes no count.
// It can pass if the library no longer calls SSL_clear during the handshake.
func TestProducerImplicitReadHandshakePreservesOccupancy(t *testing.T) {
	certificationImplicitHandshake(t, true)
}

func certificationImplicitHandshake(t *testing.T, reading bool) {
	t.Helper()
	var greeting []byte
	if reading {
		greeting = bytes.Repeat([]byte("r"), 512)
	}
	r := certificationFixtureWithGreeting(t, nil, greeting)
	line := r.command(t, "L 0")
	var index, connects, finished int
	var address uint64
	if n, err := fmt.Sscanf(line, "L %d %d %d %d", &index, &address, &connects, &finished); err != nil || n != 4 || index != 0 || address == 0 || connects != 0 || finished != 0 {
		t.Fatalf("wiring, not the property: lazy open must precede any SSL_connect or handshake: %q", line)
	}
	direction, firstIO := fragment.Sent, "SSL_write"
	if reading {
		direction, firstIO = fragment.Received, "SSL_read"
		r.expect(t, "I 0", "I ok")
	} else {
		r.expect(t, "W 0 1", "W ok")
	}
	r.peer(t)
	r.expect(t, "H 0", "H 0 1")
	first := r.next(t, direction)
	if reading {
		if !bytes.Equal(first.Payload, greeting) {
			t.Fatal("wiring, not the property: first read did not receive the known peer payload")
		}
	} else {
		peer := r.bytes(t, 1)
		if !bytes.Equal(peer[0], certificationPayload(0, 1)) || !bytes.Equal(first.Payload, peer[0]) {
			t.Fatal("wiring, not the property: first write did not move the known payload to its peer")
		}
	}
	t.Logf("PRECONDITIONS first_io=%s lazy_open=1 explicit_SSL_connect_calls=0 completed_handshakes=1 peer_confirmed_payloads=1 internal_clear_count=unavailable", firstIO)
	if first.Sequence.Occupancy == 0 || !first.Sequence.Born || first.Sequence.Number != 1 {
		t.Errorf("implicit handshake erased qualified first transfer: %+v", first.Sequence)
	}
	r.expect(t, "W 0 1", "W ok")
	next := r.next(t, fragment.Sent)
	peer := r.bytes(t, 1)
	want := uint64(2)
	if reading {
		want = 1
	}
	if !bytes.Equal(peer[0], certificationPayload(0, int(want))) || !bytes.Equal(next.Payload, peer[0]) {
		t.Fatal("wiring, not the property: following write did not move the known payload")
	}
	if next.Sequence.Occupancy != first.Sequence.Occupancy || next.Sequence.Number != want {
		t.Errorf("implicit handshake shifted later operation: first=%+v next=%+v", first.Sequence, next.Sequence)
	}
}

func TestProducerPresentProbeRefusalWithholdsOrigin(t *testing.T) {
	for _, symbol := range []string{"SSL_write", "SSL_sendfile", "SSL_clear"} {
		t.Run(symbol, func(t *testing.T) {
			requested := 0
			r := certificationFixture(t, func(o *ebpf.Options) {
				for _, p := range o.Points {
					if p.Symbol == symbol {
						requested++
					}
				}
				o.FailEntry = []string{symbol}
			})
			if requested != 1 {
				t.Fatalf("wiring, not the property: resolved requested probe count=%d", requested)
			}
			r.open(t, 0)
			r.expect(t, "E 0", "E ok")
			e := r.next(t, fragment.Sent)
			wire := r.bytes(t, 1)
			if e.Length != 512 || !bytes.Equal(wire[0], certificationPayload(0, 1)) {
				t.Fatal("wiring, not the property: surviving route did not move actual bytes")
			}
			r.stop(t)
			t.Logf("PRECONDITIONS present_probe_refusals=1 symbol=%s real_TLS_writes=1 sequence=%+v", symbol, e.Sequence)
			if !slices.Contains(r.session.Unprobed(), symbol) {
				t.Errorf("present probe refusal missing from coverage: %s", symbol)
			}
			if e.Sequence.Occupancy != 0 || e.Sequence.Born {
				t.Errorf("partial placement manufactured qualified origin: %+v", e.Sequence)
			}
		})
	}
}

func TestProducerAbsentOptionalSymbolKeepsOrigin(t *testing.T) {
	libs, err := filepath.Glob("/usr/lib/*-linux-gnu/libssl.so.3")
	if err != nil || len(libs) != 1 {
		t.Fatalf("wiring, not the property: libssl files=%v err=%v", libs, err)
	}
	data, err := os.ReadFile(libs[0])
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("SSL_sendfile\x00")
	if bytes.Count(data, old) == 0 {
		t.Fatal("wiring, not the property: original optional symbol absent")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(path, bytes.ReplaceAll(data, old, []byte("ZZZ_sendfile\x00")), 0600); err != nil {
		t.Fatal(err)
	}
	library, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := library.DynamicSymbols()
	_ = library.Close()
	if err != nil {
		t.Fatal(err)
	}
	renamed := 0
	for _, symbol := range symbols {
		if symbol.Name == "SSL_sendfile" {
			t.Fatal("wiring, not the property: optional symbol remains")
		}
		if symbol.Name == "ZZZ_sendfile" {
			renamed++
		}
	}
	if renamed != 1 {
		t.Fatalf("wiring, not the property: renamed symbols=%d", renamed)
	}
	t.Setenv("LD_LIBRARY_PATH", dir)
	r := certificationFixture(t, func(o *ebpf.Options) {
		want, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, point := range o.Points {
			actual, err := os.Stat(point.Path)
			if err != nil || point.Symbol == "SSL_sendfile" || !os.SameFile(want, actual) {
				t.Fatalf("wiring, not the property: resolver did not inspect the private library: %+v: %v", point, err)
			}
		}
	})
	r.open(t, 0)
	r.expect(t, "W 0 1", "W ok")
	e := r.next(t, fragment.Sent)
	wire := r.bytes(t, 1)
	if e.Length != 512 || !bytes.Equal(wire[0], certificationPayload(0, 1)) {
		t.Fatal("wiring, not the property: private library did not move bytes")
	}
	r.stop(t)
	t.Log("PRECONDITIONS absent_optional_symbols=1 verified_replacement_exports=1 real_TLS_writes=1")
	if len(r.session.Unprobed()) != 0 || e.Sequence.Occupancy == 0 || !e.Sequence.Born || e.Sequence.Number != 1 {
		t.Errorf("optional absence mistaken for failed present probe: unprobed=%v sequence=%+v", r.session.Unprobed(), e.Sequence)
	}
}

func TestProducerPreCoverageBirthCannotBecomeOrigin(t *testing.T) {
	var later []ebpf.Point
	r := certificationFixture(t, func(o *ebpf.Options) {
		o.DeferCaptureLive = true
		var life []ebpf.Point
		for _, p := range o.Points {
			if p.Symbol == "SSL_new" || p.Symbol == "SSL_free" || p.Symbol == "SSL_clear" {
				life = append(life, p)
			} else {
				later = append(later, p)
			}
		}
		o.Points = life
	})
	old, _ := r.open(t, 0)
	r.expect(t, "W 0 1", "W ok")
	wire := r.bytes(t, 1)
	if !bytes.Equal(wire[0], certificationPayload(0, 1)) || len(later) == 0 {
		t.Fatal("wiring, not the property: pre-coverage byte movement absent")
	}
	if err := ebpf.IndependentPlace(r.session, later); err != nil {
		t.Fatal(err)
	}
	if err := r.session.MarkCaptureLive(); err != nil {
		t.Fatal(err)
	}
	r.expect(t, "W 0 1", "W ok")
	oldEvent := r.next(t, fragment.Sent)
	r.bytes(t, 1)
	fresh, _ := r.open(t, 1)
	r.expect(t, "W 1 1", "W ok")
	newEvent := r.next(t, fragment.Sent)
	r.bytes(t, 1)
	if old == fresh || oldEvent.SSL != old || newEvent.SSL != fresh || !bytes.Equal(oldEvent.Payload, certificationPayload(0, 2)) || !bytes.Equal(newEvent.Payload, certificationPayload(1, 1)) {
		t.Fatal("wiring, not the property: old and fresh controls did not reach separate handles")
	}
	r.stop(t)
	t.Logf("PRECONDITIONS omitted_data_probes=%d pre_coverage_byte_calls=1 old_after_live=1 fresh_after_live=1", len(later))
	if oldEvent.Sequence.Born {
		t.Errorf("pre-coverage birth promoted to origin: %+v", oldEvent.Sequence)
	}
	if !newEvent.Sequence.Born || newEvent.Sequence.Number != 1 || newEvent.Sequence.Occupancy == 0 || newEvent.Sequence.Occupancy == oldEvent.Sequence.Occupancy {
		t.Errorf("fresh positive control lacks distinct known origin: old=%+v new=%+v", oldEvent.Sequence, newEvent.Sequence)
	}
}

func TestProducerSendfileMovementLeavesNumberedHole(t *testing.T) {
	r := certificationFixture(t, nil)
	r.expect(t, "K", "K ok")
	r.open(t, 0)
	capability := r.command(t, "Q 0")
	if capability != "Q 1" {
		t.Skipf("UNPROVED: connections_attempted=1 kTLS_enabled_connections=0 successful_sendfile_byte_moves=0: %s", capability)
	}
	placed := 0
	for _, p := range r.session.Placed() {
		if p.Point.Symbol == "SSL_sendfile" && p.Confirmed {
			placed++
		}
	}
	if placed != 1 {
		t.Fatalf("wiring, not the property: sendfile entry probes=%d", placed)
	}
	r.expect(t, "W 0 1", "W ok")
	first := r.next(t, fragment.Sent)
	before := r.bytes(t, 1)
	r.expect(t, "S 0", "S 512")
	moved := r.bytes(t, 1)
	r.expect(t, "W 0 1", "W ok")
	last := r.next(t, fragment.Sent)
	after := r.bytes(t, 1)
	if !bytes.Equal(before[0], certificationPayload(0, 1)) || !bytes.Equal(moved[0], certificationPayload(0, 2)) || !bytes.Equal(after[0], certificationPayload(0, 3)) || first.Length != 512 || last.Length != 512 {
		t.Fatal("wiring, not the property: real sendfile and its bracketing writes did not reach the peer")
	}
	r.stop(t)
	t.Log("PRECONDITIONS kTLS_enabled_connections=1 confirmed_sendfile_entry_probes=1 successful_sendfile_byte_moves=1 sendfile_peer_bytes=512")
	if first.Sequence.Occupancy == 0 || !first.Sequence.Born || first.Sequence.Number != 1 || last.Sequence.Occupancy != first.Sequence.Occupancy || last.Sequence.Number != 3 {
		t.Errorf("uncatalogued byte movement vanished from numbering: first=%+v last=%+v", first.Sequence, last.Sequence)
	}
	if !bytes.Equal(first.Payload, before[0]) || !bytes.Equal(last.Payload, after[0]) {
		t.Error("numbered hole was replaced with bytes from another operation")
	}
	final, err := r.session.Settled(certificationHandle(last))
	if err != nil {
		t.Fatal(err)
	}
	if !final.Final.Known || final.Final.Sent.Last != 3 || final.Final.Sent.Dropped != 0 {
		t.Errorf("uncatalogued movement mistaken for reservation drop: %+v", final)
	}
}
