package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/huzenkon/waf-firewall/internal/api"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/engine"
)

func main() {
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
