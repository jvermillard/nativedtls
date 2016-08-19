package nativedtls

/*
#cgo LDFLAGS: /home/jvermillar/sandbox/openssl/libssl.a /home/jvermillar/sandbox/openssl/libcrypto.a -ldl
#cgo CFLAGS: -g -Wno-deprecated -I/home/jvermillar/sandbox/openssl/include

#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>


extern int go_session_bio_write(BIO* bio, char* buf, int num);
extern int go_session_bio_read(BIO* bio, char* buf, int num);
extern int go_session_bio_free(BIO* bio);

extern unsigned int go_server_psk_callback(SSL *ssl, char *identity, char *psk, unsigned int max_psk_len);

extern int generate_cookie_callback(SSL* ssl, unsigned char* cookie, unsigned int *cookie_len);
extern int verify_cookie_callback(SSL* ssl, unsigned char* cookie, unsigned int cookie_len);

extern int get_errno(void);
extern void set_errno(int e);

static long go_session_bio_ctrl(BIO *bp,int cmd,long larg,void *parg) {
	//always return operation not supported
	//http://www.openssl.org/docs/crypto/BIO_ctrl.html
	//printf("go_bio_ctrl %d\n", cmd);
	return 1;
}

static int write_wrapper(BIO* bio,const char* data, int n) {
	return go_session_bio_write(bio,data,n);
}

static int go_session_bio_create( BIO *b ) {
	BIO_set_init(b,1);
	//BIO_set_num(b,-1);
	//BIO_set_ptr(b,NULL);
	BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_WRITE);
	printf("bio created\n");
	return 1;
}

// a BIO for a client conencted to our server
static BIO_METHOD* go_session_bio_method;

static int init_session_bio_method() {
	go_session_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK,"go session dtls");
	BIO_meth_set_write(go_session_bio_method,write_wrapper);
	BIO_meth_set_read(go_session_bio_method,go_session_bio_read);
	BIO_meth_set_ctrl(go_session_bio_method,go_session_bio_ctrl);
	BIO_meth_set_create(go_session_bio_method,go_session_bio_create);
	BIO_meth_set_destroy(go_session_bio_method,go_session_bio_free);

}

//{
//	BIO_TYPE_SOURCE_SINK,
//	"go session dtls",
//	(int (*)(BIO *, const char *, int))go_session_bio_write,
//	go_session_bio_read,
//	NULL,
//	NULL,
//	go_session_bio_ctrl, // ctrl
//	go_session_bio_create, // new
//	go_session_bio_free // delete
//};

static void init_server_ctx(SSL_CTX *ctx) {
	SSL_CTX_set_min_proto_version(ctx, 0xFEFD); // 1.2
	SSL_CTX_set_max_proto_version(ctx, 0xFEFD); // 1.2
//	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, &generate_cookie_callback);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie_callback);

}

static BIO_METHOD* BIO_go_session() {
	return go_session_bio_method;
}

static void setGoSessionId(BIO* bio, unsigned int clientId) {
	unsigned int * pId = malloc(sizeof(unsigned int));
	*pId = clientId;
	BIO_set_data(bio,pId);
}
static unsigned int server_psk_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
	return go_server_psk_callback(ssl,identity,(char*)psk,max_psk_len);
}

static void set_psk_callback(SSL *ssl) {
	SSL_set_psk_server_callback(ssl,&server_psk_callback);
}

static void set_cookie_option(SSL *ssl) {
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
}

*/
import "C"
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// init server BIO method
func server_bio_method_init() {
	fmt.Println("init session BIO")
	C.init_session_bio_method()
}

func NewServerDTLSContext() *DTLSCtx {
	ctx := C.SSL_CTX_new(C.DTLSv1_2_server_method())
	if ctx == nil {
		panic("error creating SSL context")
	}

	C.init_server_ctx(ctx)

	self := DTLSCtx{ctx}
	return &self
}

type DTLSServer struct {
	started        bool
	ctx            *C.SSL_CTX
	sessions       map[string]*session
	conn           net.PacketConn // socket for receiving/writting data
	pskCallback    func(pskId string) []byte
	createdSession chan struct {
		sess *session
		err  error
	}
	cookieSecret []byte // the secret used for cookie verification
}

// DTLS session between a client and the server
type session struct {
	addr   net.Addr
	ssl    *C.SSL
	bio    *C.BIO
	server *DTLSServer
	rcvd   chan []byte // where we push raw byte comming from the server socket
}

func NewDTLSServer(ctx *DTLSCtx, conn net.PacketConn) *DTLSServer {
	secret := make([]byte, 32)
	if n, err := rand.Read(secret); n != 32 || err != nil {
		panic(err)
	}
	server := DTLSServer{false, ctx.ctx, make(map[string]*session), conn, nil, make(chan struct {
		sess *session
		err  error
	}), secret}

	return &server
}

func (s *DTLSServer) SetPskCallback(callback func(string) []byte) {
	s.pskCallback = callback
}

var sessions = make(map[int32]*session)
var nextSessionId int32 = 0

func (s *DTLSServer) newSession(addr net.Addr) *session {
	fmt.Println("create new session")
	ssl := C.SSL_new(s.ctx)
	id := atomic.AddInt32(&nextSessionId, 1)

	// add the PSK callback
	if s.pskCallback != nil {
		fmt.Println("callback set")
		C.set_psk_callback(ssl)
	} else {
		fmt.Println("no callback")
	}

	// dump ciphers
	index := C.int(0)
	for {
		next := C.SSL_get_cipher_list(ssl, index)
		if next != nil {
			fmt.Println("chiper", index, C.GoString(next))
			index = index + 1
		} else {
			break
		}
	}

	// create the BIO

	bio := C.BIO_new(C.BIO_go_session())

	if bio == nil {
		fmt.Println("BIO creation error")
	}
	C.SSL_set_bio(ssl, bio, bio)

	sess := session{addr: addr, ssl: ssl, bio: bio, server: s, rcvd: make(chan []byte)}

	sessions[id] = &sess
	// the ID is used as link between the Go and C lang since sharing Go pointers is
	// so the C is going to own the pointer to the id value
	C.setGoSessionId(bio, C.uint(id))

	// this session should start by doing a server handshake
	C.set_cookie_option(ssl)
	C.SSL_set_accept_state(ssl)
	C.DTLSv1_listen
	return &sess
}

// Wait for new DTLS connection and provide a unciphered net.Conn
// this method should be called in a loop, it will be in charge of reading the UDP server socket
// and feeding the different sesssions
func (s *DTLSServer) Accept() (net.Conn, error) {
	if !s.started {
		go s.loop()
	}

	// wait for sessions
	res := <-s.createdSession

	return res.sess, res.err
}

// server loop, read from socket and send event to the correspoing channels
func (s *DTLSServer) loop() {
	buffer := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFrom(buffer)
		if err != nil {
			s.createdSession <- struct {
				sess *session
				err  error
			}{sess: nil, err: err}

		}
		tmpBuff := buffer[:n]

		// do we have a session for this address?
		sess := s.sessions[addr.String()]
		if sess == nil {
			// create a new session, start it feed it and return it
			sess = s.newSession(addr)

			s.sessions[addr.String()] = sess
			s.createdSession <- struct {
				sess *session
				err  error
			}{sess: sess, err: nil}
		}
		// push the data to the session and wait for more data
		fmt.Println("push to bio")
		sess.rcvd <- tmpBuff
		fmt.Println("push to bio done")
	}
}

func (s *session) Close() error {
	// TODO
	return nil
}

func (s *session) LocalAddr() net.Addr {
	return nil
}

func (s *session) RemoteAddr() net.Addr {
	return s.addr
}

func (s *session) Read(b []byte) (n int, err error) {
	// TODO test if closed
	length := len(b)

	fmt.Println("SSL READ")

	ret := C.SSL_read(s.ssl, unsafe.Pointer(&b[0]), C.int(length))
	fmt.Println("SSL READ done")
	if err := s.getError(ret); err != nil {
		return 0, err
	}
	// if there's no error, but a return value of 0
	// let's say it's an EOF
	if ret == 0 {
		return 0, io.EOF
	}
	return int(ret), nil
}

func (s *session) Write(b []byte) (int, error) {
	// TODO test is connected
	length := len(b)
	ret := C.SSL_write(s.ssl, unsafe.Pointer(&b[0]), C.int(length))
	if err := s.getError(ret); err != nil {
		return 0, err
	}

	return int(ret), nil
}

func (s *session) getError(ret C.int) error {
	err := C.SSL_get_error(s.ssl, ret)
	switch err {
	case C.SSL_ERROR_NONE:
		return nil
	case C.SSL_ERROR_ZERO_RETURN:
		return io.EOF
	case C.SSL_ERROR_SYSCALL:
		if int(C.ERR_peek_error()) != 0 {
			return syscall.Errno(C.get_errno())
		}

	default:
		msg := ""
		for {
			errCode := C.ERR_get_error()
			if errCode == 0 {
				break
			}
			msg += getErrorString(errCode)
		}
		C.ERR_clear_error()
		return errors.New(msg)
	}
	return nil
}

func (s *session) SetDeadline(t time.Time) error {
	return nil
}
func (s *session) SetReadDeadline(t time.Time) error {
	return nil
}
func (s *session) SetWriteDeadline(t time.Time) error {
	return nil
}

//export go_session_bio_read
func go_session_bio_read(bio *C.BIO, buf *C.char, num C.int) C.int {
	sess := sessions[*(*int32)(C.BIO_get_data(bio))]

	fmt.Println("session_bio_read")
	socketData := <-sess.rcvd

	data := goSliceFromCString(buf, int(num))

	if data == nil {
		return 0
	}
	wrote := copy(data, socketData)
	fmt.Println("session_bio_read done")

	return C.int(wrote)
}

//export go_session_bio_write
func go_session_bio_write(bio *C.BIO, buf *C.char, num C.int) C.int {
	fmt.Println("write conn")
	session := sessions[*(*int32)(C.BIO_get_data(bio))]
	data := goSliceFromCString(buf, int(num))
	n, err := session.server.conn.WriteTo(data, session.addr)
	if err != nil && err != io.EOF {
		//We expect either a syscall error
		//or a netOp error wrapping a syscall error
	TESTERR:
		switch err.(type) {
		case syscall.Errno:
			C.set_errno(C.int(err.(syscall.Errno)))
		case *net.OpError:
			err = err.(*net.OpError).Err
			break TESTERR
		}
		return C.int(-1)
	}
	fmt.Println("write conn", n)
	return C.int(n)
}

//export go_session_bio_free
func go_session_bio_free(bio *C.BIO) C.int {
	// TODO: we should inform the session is closed (if needed)

	// some flags magic
	if C.int(C.BIO_get_shutdown(bio)) != 0 {
		C.BIO_set_data(bio, nil)
		C.BIO_set_flags(bio, 0)
		C.BIO_set_init(bio, 0)
	}
	return C.int(1)
}

//export go_server_psk_callback
func go_server_psk_callback(ssl *C.SSL, identity *C.char, psk *C.char, max_psk_len C.uint) C.uint {
	bio := C.SSL_get_rbio(ssl)
	sess := sessions[*(*int32)(C.BIO_get_data(bio))]

	if sess.server.pskCallback == nil {
		return 0
	}

	// TODO test nil ?
	goPskId := C.GoString(identity)

	serverPsk := sess.server.pskCallback(goPskId)

	if serverPsk == nil {
		return 0
	}

	if len(serverPsk) >= int(max_psk_len) {
		fmt.Println("PSK too large")
		return 0
	}

	targetPsk := goSliceFromCString(psk, int(max_psk_len))
	return C.uint(copy(targetPsk, serverPsk))
}

//export generate_cookie_callback
func generate_cookie_callback(ssl *C.SSL, cookie *C.uchar, cookie_len *C.uint) C.int {
	bio := C.SSL_get_rbio(ssl)
	sess := sessions[*(*int32)(C.BIO_get_data(bio))]

	mac := hmac.New(sha256.New, sess.server.cookieSecret)
	mac.Write([]byte(sess.RemoteAddr().String()))
	cookieValue := mac.Sum(nil)

	if len(cookieValue) >= int(*cookie_len) {
		fmt.Println("no enough cookie space (should not happen..)")
		return 0
	}

	data := goSliceFromUCString(cookie, int(*cookie_len))

	*cookie_len = C.uint(copy(data, cookieValue))
	return 1

}

//export verify_cookie_callback
func verify_cookie_callback(ssl *C.SSL, cookie *C.uchar, cookie_len C.uint) C.int {
	bio := C.SSL_get_rbio(ssl)
	sess := sessions[*(*int32)(C.BIO_get_data(bio))]

	mac := hmac.New(sha256.New, sess.server.cookieSecret)
	mac.Write([]byte(sess.RemoteAddr().String()))
	cookieValue := mac.Sum(nil)

	if len(cookieValue) != int(cookie_len) {
		return 0
	}

	data := goSliceFromUCString(cookie, int(cookie_len))

	if bytes.Equal(data, cookieValue) {
		return 1
	} else {
		return 0
	}

}
