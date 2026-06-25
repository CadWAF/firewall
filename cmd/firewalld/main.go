package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/huzenkon/waf-firewall/internal/api"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/engine"
)

func main() {
	if len(os.Args) > 1 {
		delegateToCLI()
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	defer eng.Close()

	h := &api.Handler{Cfg: cfg, Engine: eng}
	r := chi.NewRouter()
	api.Register(r, h)

	go func() {
		log.Printf("firewalld v%s listening on %s (iface=%s)", config.Version, cfg.ListenAddr, cfg.Iface)
		if err := http.ListenAndServe(cfg.ListenAddr, r); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}

func delegateToCLI() {
	cli, err := exec.LookPath("firewallctl")
	if err != nil {
		cli = "/usr/local/bin/firewallctl"
	}
	args := append([]string{"firewallctl"}, os.Args[1:]...)
	if err := syscall.Exec(cli, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "firewalld is the daemon; run: firewallctl %s\n", os.Args[1])
		os.Exit(1)
	}
}
