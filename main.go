package main

import (
	"flag"
	"fmt"
	"github.com/veraison/services/verification/api"
	//"github.com/dreemkiller/VeracruzVerifier/verifier"
	"github.com/veraison/services/verification/verifier"
	"github.com/dreemkiller/VeracruzVerifier/session"
	"github.com/veraison/services/config"
	"github.com/veraison/services/vtsclient"
)

func main() {
	fmt.Println("Hello, World!")

	var listenAddress string

	flag.StringVar(&listenAddress, "l", "", "Address to listen on")
	flag.Parse()

	session_manager := session.NewSessionManager()

	// verifier,err := verifier.NewVerifier()
	// if err != nil {
	// 	fmt.Println("NewVerifier failed:", err)
	// 	return
	// }

	vtsClientCfg := config.Store{
		"vts-server.addr": "vts:50051",
	}
	vtsClient := vtsclient.NewGRPC(vtsClientCfg)

	verifierCfg := config.Store {
		// empty for now?
	}
	myVerifier := verifier.New(verifierCfg, vtsClient)

	handler := api.NewHandler(session_manager, myVerifier)

	router := api.NewRouter(handler)
	err := router.Run()
	if err != nil {
		fmt.Println("Router failed to run")
	}
}
