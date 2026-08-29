package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/huzenkon/waf-firewall/internal/auth"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/engine"
	"github.com/huzenkon/waf-firewall/internal/parser"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

type Handler struct {
	Cfg    *config.Config
	Engine *engine.Engine
}

func Register(r chi.Router, h *Handler) {
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/health", h.health)

	r.Group(func(r chi.Router) {
		r.Use(auth.Bearer(h.Cfg.APIKey))

		r.Get("/api/v1/ips/whitelist", h.listWhitelist)
		r.Post("/api/v1/ips/whitelist", h.addWhitelist)
		r.Delete("/api/v1/ips/whitelist/{ip}", h.deleteWhitelist)

		r.Get("/api/v1/ips/blocklist", h.listBlocklist)
		r.Post("/api/v1/ips/blocklist", h.addBlocklist)
		r.Delete("/api/v1/ips/blocklist/{ip}", h.deleteBlocklist)

		r.Get("/api/v1/ports", h.getPorts)
		r.Put("/api/v1/ports", h.putPorts)

		r.Get("/api/v1/rules", h.listRules)
		r.Post("/api/v1/rules", h.addRule)
		r.Delete("/api/v1/rules/{id}", h.deleteRule)

		r.Post("/api/v1/reload", h.reload)
		r.Get("/api/v1/stats", h.stats)
	})
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.Engine.Health())
}

func (h *Handler) listWhitelist(w http.ResponseWriter, r *http.Request) {
	st := h.Engine.State()
	if st == nil {
		writeJSON(w, map[string]any{"ips": []string{}})
		return
	}
	writeJSON(w, map[string]any{"ips": st.Whitelist})
}

type ipRequest struct {
	IP string `json:"ip"`
}

func (h *Handler) addWhitelist(w http.ResponseWriter, r *http.Request) {
	var req ipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"ip required"}`, http.StatusBadRequest)
		return
	}
	if _, err := parser.ParseLine(req.IP, parser.ActionPass); err != nil || !isSimpleIP(req.IP) {
		http.Error(w, `{"error":"invalid ip"}`, http.StatusBadRequest)
		return
	}
	if err := parser.AppendIPToFile(h.Cfg.AllowPath(), req.IP); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "ip": req.IP})
}

func (h *Handler) deleteWhitelist(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if err := parser.RemoveIPFromFile(h.Cfg.AllowPath(), ip); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) listBlocklist(w http.ResponseWriter, r *http.Request) {
	st := h.Engine.State()
	if st == nil {
		writeJSON(w, map[string]any{"ips": []string{}})
		return
	}
	writeJSON(w, map[string]any{"ips": st.Blocklist})
}

func (h *Handler) addBlocklist(w http.ResponseWriter, r *http.Request) {
	var req ipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, `{"error":"ip required"}`, http.StatusBadRequest)
		return
	}
	if _, err := parser.ParseLine(req.IP, parser.ActionDrop); err != nil || !isSimpleIP(req.IP) {
		http.Error(w, `{"error":"invalid ip"}`, http.StatusBadRequest)
		return
	}
	if err := parser.AppendIPToFile(h.Cfg.DenyPath(), req.IP); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "ip": req.IP})
}

func (h *Handler) deleteBlocklist(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if err := parser.RemoveIPFromFile(h.Cfg.DenyPath(), ip); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) getPorts(w http.ResponseWriter, r *http.Request) {
	st := h.Engine.State()
	if st == nil || st.Ports == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, map[string]any{
		"tcp_in":          st.Ports.TCPIn,
		"udp_in":          st.Ports.UDPIn,
		"tcp_out":         st.Ports.TCPOut,
		"udp_out":         st.Ports.UDPOut,
		"allow_localhost": st.Ports.AllowLocalhost,
	})
}

type portsRequest struct {
	TCPIn          *[]uint16 `json:"tcp_in"`
	UDPIn          *[]uint16 `json:"udp_in"`
	TCPOut         *[]uint16 `json:"tcp_out"`
	UDPOut         *[]uint16 `json:"udp_out"`
	AllowLocalhost *bool     `json:"allow_localhost"`
}

func (h *Handler) putPorts(w http.ResponseWriter, r *http.Request) {
	var req portsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	pc, err := config.LoadPorts(h.Cfg.PortsPath())
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if req.TCPIn != nil {
		pc.TCPIn = *req.TCPIn
	}
	if req.UDPIn != nil {
		pc.UDPIn = *req.UDPIn
	}
	if req.TCPOut != nil {
		pc.TCPOut = *req.TCPOut
	}
	if req.UDPOut != nil {
		pc.UDPOut = *req.UDPOut
	}
	if req.AllowLocalhost != nil {
		pc.AllowLocalhost = *req.AllowLocalhost
	}
	policy.EnsureSafePorts(pc)
	if err := policy.ValidateSSHReachable(h.Cfg.AllowPath(), pc); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if err := config.SavePorts(h.Cfg.PortsPath(), pc); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) listRules(w http.ResponseWriter, r *http.Request) {
	st := h.Engine.State()
	rules := []map[string]any{}
	if st != nil {
		for i, rule := range st.Rules {
			rules = append(rules, map[string]any{
				"id":     i,
				"rule":   rule.Raw,
				"action": rule.Action,
				"file":   rule.File,
			})
		}
	}
	writeJSON(w, map[string]any{"rules": rules})
}

type ruleRequest struct {
	Rule   string `json:"rule"`
	File   string `json:"file"`
	Action string `json:"action"`
}

func (h *Handler) addRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Rule == "" {
		http.Error(w, `{"error":"rule required"}`, http.StatusBadRequest)
		return
	}
	path := h.Cfg.AllowPath()
	action := parser.ActionPass
	if req.Action == "drop" || req.File == "deny" {
		path = h.Cfg.DenyPath()
		action = parser.ActionDrop
	}
	if _, err := parser.ParseLine(req.Rule, action); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if err := parser.AppendRuleToFile(path, req.Rule); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) deleteRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}
	file := r.URL.Query().Get("file")
	path := h.Cfg.AllowPath()
	if file == "deny" {
		path = h.Cfg.DenyPath()
	}
	if err := parser.RemoveRuleFromFile(path, id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) reload(w http.ResponseWriter, r *http.Request) {
	if err := h.Engine.Reload(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	s, err := h.Engine.Stats()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"xdp": map[string]uint64{"pass": s.XDPPass, "drop": s.XDPDrop},
		"tc":  map[string]uint64{"pass": s.TCPass, "drop": s.TCDrop},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func isSimpleIP(s string) bool {
	_, err := parser.ParseLine(s, parser.ActionPass)
	return err == nil && !containsPipe(s)
}

func containsPipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			return true
		}
	}
	return false
}
