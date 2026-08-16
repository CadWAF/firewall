grep -E 'reload_fail|rollback_fail|whitelist_cleared|bpf_tcp_in_empty|bpf_tcp_in_keys_missing|bpf_whitelist_keys_missing|map_refresh' /var/log/firewalld-diag.log
curl -s http://127.0.0.1:9090/health
