package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

/*
#cgo CFLAGS: -g -Wall
#cgo LDFLAGS: -lmodsecurity
#include <stdlib.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

#define N_INTERVENTION_STATUS 200


int checkTransaction(Transaction *transaction) {

	//ModSecurityIntervention intervention;
	//intervention.status = 200;
    //intervention.url = NULL;
    //intervention.log = NULL;
	//intervention.disruptive = 0;
	//
	//if (msc_intervention(transaction, &intervention) == 0) {
    //    fprintf(stderr, "No intervention required!\n");
    //    return 0;
    //} else {
	//		fprintf(stderr, "We should intervene...!\n");
	//		return 1;
    //}
    //return 0;

    ModSecurityIntervention intervention;
    intervention.status = N_INTERVENTION_STATUS;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;

    int z = msc_intervention(transaction, &intervention);

    if (z == 0)
    {
        return N_INTERVENTION_STATUS;
    }

    if (intervention.log == NULL)
    {
        intervention.log = "(no log message was specified)";
    }

    if (intervention.status == 301 || intervention.status == 302
        ||intervention.status == 303 || intervention.status == 307)
    {
        if (intervention.url != NULL)
        {
            return 301;
        }
    }

    if (intervention.status != N_INTERVENTION_STATUS)
    {
        return intervention.status;
    }

    return N_INTERVENTION_STATUS;
}



unsigned char* charToUchar(char *Data) {
    return (unsigned char*) Data;
}

*/
import "C"

var modsec = C.msc_init()
var rules = C.msc_create_rules_set()

func main() {

	log.Print("listen 9000")

	listener, err := net.Listen("tcp", "127.0.0.1:9000")
	if err != nil {
		log.Printf("error create listener, %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	var errC *C.char
	defer C.free(unsafe.Pointer(errC))

	defer C.free(unsafe.Pointer(modsec))

	conninfo := C.CString("Mod-security SPOE agent")
	defer C.free(unsafe.Pointer(conninfo))
	C.msc_set_connector_info(modsec, conninfo)

	ruleURI := C.CString("basic_rules.conf")
	defer C.free(unsafe.Pointer(ruleURI))

	defer C.free(unsafe.Pointer(rules))

	ret := C.msc_rules_add_file(rules, ruleURI, &errC)
	if int(ret) < 0 {
		log.Fatalf(C.GoString(errC))
	}

	mux := http.NewServeMux()
	mux.Handle("/", ccHandler{})
	http.Serve(listener, mux)
}

type ccHandler struct{}

func (ccHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	//log.Println(req.Header)
	var transaction *C.Transaction
	defer C.free(unsafe.Pointer(transaction))

	transaction = C.msc_new_transaction(modsec, rules, nil)
	defer C.msc_transaction_cleanup(transaction)

	ipPort := strings.Split(req.RemoteAddr, ":")
	port, err := strconv.Atoi(ipPort[1])
	if err != nil {
		log.Fatalf("Error processing conection: ", err)
	}
	ret := C.msc_process_connection(transaction, C.CString(ipPort[0]), C.int(port), C.CString("127.0.0.9"), 9000)
	// msr->t, client_ip, client_port, r->server->server_hostname, (int) r->server->port
	if ret < 1 {
		log.Fatalf("Error processing conection: %d", int(ret))
	}

	C.msc_process_uri(transaction, C.CString(req.URL.RawPath), C.CString(req.Method), C.CString(req.Proto[5:]))
	// msr->t, r->unparsed_uri, r->method, r->protocol + offset

	for k, v := range req.Header {
		C.msc_add_request_header(transaction, C.charToUchar(C.CString(k)), C.charToUchar(C.CString(strings.Join(v, ";"))))
	}

	C.msc_process_request_headers(transaction)
	C.msc_process_request_body(transaction)
	// THIS IS WHAT CAUSES INTERVENTION - TEST WITH OTHER CASES!!
	//C.msc_process_response_headers(transaction, 200, C.CString("HTTP 1.!"));
	C.msc_process_response_body(transaction)

	C.msc_process_logging(transaction)

	intervention := C.checkTransaction(transaction)

	log.Printf("Intervetion: %d", int(intervention))
	fmt.Fprintf(w, "hello world\n")
	return
}
