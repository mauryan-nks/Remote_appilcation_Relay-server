package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"vismrit/remote/internal/signaling"
)

func main() {
	addr := flag.String("addr", ":45991", "signal TCP listen address")
	_ = flag.String("udp", "", "deprecated; UDP discovery is disabled in TCP-only mode")
	apiURL := flag.String("api", os.Getenv("REMOTE_API_URL"), "CI4 control-plane API URL")
	cert := flag.String("cert", "", "optional TLS certificate PEM")
	key := flag.String("key", "", "optional TLS private key PEM")
	flag.Parse()
	if *apiURL == "" {
		fmt.Fprintln(os.Stderr, "REMOTE_API_URL or -api is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv := signaling.NewServer(&signaling.HTTPVerifier{APIURL: *apiURL})
	fmt.Printf("signal server TCP/TLS %s, TCP-only mode, API %s\n", *addr, *apiURL)
	if err := srv.ListenAndServe(ctx, *addr, *cert, *key); err != nil && ctx.Err() == nil {
		panic(err)
	}
}
