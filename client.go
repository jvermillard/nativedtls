package nativedtls

/*
#cgo LDFLAGS: /home/jvermillar/sandbox/openssl/libssl.a /home/jvermillar/sandbox/openssl/libcrypto.a -ldl
#cgo CFLAGS: -g -Wno-deprecated -I/home/jvermillar/sandbox/openssl/include

#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <internal/bio.h>

extern int go_conn_bio_write(BIO* bio, char* buf, int num);
extern int go_conn_bio_read(BIO* bio, char* buf, int num);
extern int go_conn_bio_free(BIO* bio);

extern unsigned int go_psk_callback(SSL *ssl, char *hint, char *identity, unsigned int max_identity_len, char *psk, unsigned int max_psk_len);


static int get_errno(void)
{
	return errno;
}

static void set_errno(int e)
{
	errno = e;
}

static long go_bio_ctrl(BIO *bp,int cmd,long larg,void *parg) {
	//always return operation not supported
	//http://www.openssl.org/docs/crypto/BIO_ctrl.html
	//printf("go_bio_ctrl %d\n", cmd);
	return 1;
}

static int go_bio_create( BIO *b ) {
	BIO_set_init(b,1);
	//BIO_set_num(b,-1);
	//BIO_set_ptr(b,NULL);
	BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_WRITE);
	return 1;
}

static int go_bio_destroy( BIO *b ) {
	free(BIO_get_data(b));
	return 0;
}

static long go_bio_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp) {
	return 0;
}

static BIO_METHOD go_bio_method = {
	BIO_TYPE_SOURCE_SINK,
	"go dtls",
	(int (*)(BIO *, const char *, int))go_conn_bio_write,
	go_conn_bio_read,
	NULL,
	NULL,
	go_bio_ctrl, // ctrl
	go_bio_create, // new
	go_conn_bio_free // delete
};
static BIO_METHOD* BIO_go() {
	return &go_bio_method;
}

static void init_lib() {
	SSL_library_init();
	ERR_load_BIO_strings();
	SSL_load_error_strings();
}

static void set_proto_1_2(SSL_CTX *ctx) {
	SSL_CTX_set_min_proto_version(ctx, 0xFEFD); // 1.2
	SSL_CTX_set_max_proto_version(ctx, 0xFEFD); // 1.2
}

static unsigned int psk_callback(SSL *ssl, const char *hint,
        char *identity, unsigned int max_identity_len,
        unsigned char *psk, unsigned int max_psk_len) {
	return go_psk_callback(ssl,hint,identity,max_identity_len,(char*)psk,max_psk_len);
}

static void init_ctx(SSL_CTX *ctx) {
	SSL_CTX_set_read_ahead(ctx, 1);

	//SSL_CTX_set_psk_client_callback(ctx,&psk_callback);

	SSL_CTX_set_psk_client_callback(ctx,&psk_callback);
}

static void setGoClientId(BIO* bio, unsigned int clientId) {
	unsigned int * pId = malloc(sizeof(unsigned int));
	*pId = clientId;
	BIO_set_data(bio,pId);
}

*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

import "net"

// functions called by CGO

//export go_conn_bio_write
func go_conn_bio_write(bio *C.BIO, buf *C.char, num C.int) C.int {

	client := clients[*(*int32)(C.BIO_get_data(bio))]
	data := goSliceFromCString(buf, int(num))
	n, err := client.conn.Write(data)
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
	return C.int(n)
}

//export go_conn_bio_read
func go_conn_bio_read(bio *C.BIO, buf *C.char, num C.int) C.int {
	client := clients[*(*int32)(C.BIO_get_data(bio))]
	data := goSliceFromCString(buf, int(num))
	n, err := client.conn.Read(data)
	if err == nil {
		return C.int(n)
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return 0
	}
	//We expect either a syscall error
	//or a netOp error wrapping a syscall error
	fmt.Println(err)
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

//export go_conn_bio_free
func go_conn_bio_free(bio *C.BIO) C.int {
	client := clients[*(*int32)(C.BIO_get_data(bio))]
	client.Close()
	if C.int(C.BIO_get_shutdown(bio)) != 0 {
		C.BIO_set_data(bio, nil)
		C.BIO_set_flags(bio, 0)
		C.BIO_set_init(bio, 0)
	}
	return C.int(1)
}

//export go_psk_callback
func go_psk_callback(ssl *C.SSL, hint *C.char, identity *C.char, max_identity_len C.uint, psk *C.char, max_psk_len C.uint) C.uint {
	bio := C.SSL_get_rbio(ssl)
	client := clients[*(*int32)(C.BIO_get_data(bio))]

	if client.pskId == nil || client.psk == nil {
		return 0
	}

	if len(*client.pskId) >= int(max_identity_len) || len(client.psk) >= int(max_psk_len) {
		fmt.Println("PSKID or PSK too large")
		return 0
	}
	targetId := goSliceFromCString(identity, int(max_identity_len))
	copy(targetId, *client.pskId)
	targetPsk := goSliceFromCString(psk, int(max_psk_len))
	return C.uint(copy(targetPsk, client.psk))
}

func init() {
	// low level init of OpenSSL
	C.init_lib()

	// init server BIO
	server_bio_method_init()
}

// Context used for creating a DTLS connection.
// where you configure global parameters
type DTLSCtx struct {
	ctx *C.SSL_CTX
}

func NewDTLSContext() *DTLSCtx {
	ctx := C.SSL_CTX_new(C.DTLSv1_2_client_method())
	if ctx == nil {
		panic("error creating SSL context")
	}

	C.set_proto_1_2(ctx)
	C.init_ctx(ctx)

	self := DTLSCtx{ctx}
	return &self
}

func (ctx *DTLSCtx) SetCipherList(ciphers string) bool {
	ret := int(C.SSL_CTX_set_cipher_list(ctx.ctx, C.CString(ciphers)))
	return ret == 1
}

// TODO: set verify mode?

type DTLSClient struct {
	closed    bool
	connected int32 // connection handshake was done, atomic (0 false, 1 true)
	bio       *C.BIO
	ctx       *C.SSL_CTX
	ssl       *C.SSL
	conn      net.Conn
	pskId     *string
	psk       []byte
}

var nextId int32 = 0

var clients = make(map[int32]*DTLSClient)

// Create a DTLSClient implementing the net.Conn interface
func NewDTLSClient(dtlsCtx *DTLSCtx, conn net.Conn) *DTLSClient {
	ssl := C.SSL_new(dtlsCtx.ctx)

	id := atomic.AddInt32(&nextId, 1)

	self := DTLSClient{false, 0, C.BIO_new(C.BIO_go()), dtlsCtx.ctx, ssl, conn, nil, nil}
	clients[id] = &self

	C.SSL_set_bio(self.ssl, self.bio, self.bio)

	// the ID is used as link between the Go and C lang since sharing Go pointers is
	// so the C is going to own the pointer to the id value
	C.setGoClientId(self.bio, C.uint(id))
	return &self
}

func (c *DTLSClient) connect() error {
	ret := C.SSL_connect(c.ssl)
	if err := c.getError(ret); err != nil {
		return err
	}
	return nil
}

func (c *DTLSClient) SetPSK(identity string, psk []byte) {
	c.psk = psk
	c.pskId = &identity
}

func (c *DTLSClient) Read(b []byte) (n int, err error) {
	if atomic.CompareAndSwapInt32(&c.connected, 0, 1) {
		if err := c.connect(); err != nil {
			return 0, err
		}
	}
	length := len(b)
	ret := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(length))
	if err := c.getError(ret); err != nil {
		return 0, err
	}
	// if there's no error, but a return value of 0
	// let's say it's an EOF
	if ret == 0 {
		return 0, io.EOF
	}
	return int(ret), nil
}

func (c *DTLSClient) Write(b []byte) (int, error) {
	if atomic.CompareAndSwapInt32(&c.connected, 0, 1) {
		if err := c.connect(); err != nil {
			return 0, err
		}
	}
	length := len(b)
	ret := C.SSL_write(c.ssl, unsafe.Pointer(&b[0]), C.int(length))
	if err := c.getError(ret); err != nil {
		return 0, err
	}

	return int(ret), nil
}

func (c *DTLSClient) LocalAddr() net.Addr {
	return c.LocalAddr()
}

func (c *DTLSClient) RemoteAddr() net.Addr {
	return c.RemoteAddr()
}

func (c *DTLSClient) SetDeadline(t time.Time) error {
	return nil
}
func (c *DTLSClient) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *DTLSClient) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *DTLSClient) getError(ret C.int) error {
	err := C.SSL_get_error(c.ssl, ret)
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

func getErrorString(code C.ulong) string {
	if code == 0 {
		return ""
	}
	msg := fmt.Sprintf("%s:%s:%s\n",
		C.GoString(C.ERR_lib_error_string(code)),
		C.GoString(C.ERR_func_error_string(code)),
		C.GoString(C.ERR_reason_error_string(code)))
	if len(msg) == 4 { //being lazy here, all the strings were empty
		return ""
	}
	//Check for extra line data
	var file *C.char
	var line C.int
	var data *C.char
	var flags C.int
	if int(C.ERR_get_error_line_data(&file, &line, &data, &flags)) != 0 {
		msg += fmt.Sprintf("%s:%s", C.GoString(file), int(line))
		if flags&C.ERR_TXT_STRING != 0 {
			msg += ":" + C.GoString(data)
		}
		if flags&C.ERR_TXT_MALLOCED != 0 {
			C.CRYPTO_free(unsafe.Pointer(data), C.CString(""), 0)
		}
	}
	return msg
}

func (c *DTLSClient) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	defer func() {
		C.SSL_free(c.ssl)
	}()

	ret := C.SSL_shutdown(c.ssl)
	if int(ret) == 0 {
		ret = C.SSL_shutdown(c.ssl)
		if int(ret) != 1 {
			return c.getError(ret)
		}
	}
	return nil
}

// Provides a zero copy interface for returning a go slice backed by a c array.
func goSliceFromCString(cArray *C.char, size int) (cslice []byte) {
	//See http://code.google.com/p/go-wiki/wiki/cgo
	//It turns out it's really easy to
	//make a string from a *C.char and vise versa.
	//not so easy to write to a c array.
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&cslice)))
	sliceHeader.Cap = size
	sliceHeader.Len = size
	sliceHeader.Data = uintptr(unsafe.Pointer(cArray))
	return
}
