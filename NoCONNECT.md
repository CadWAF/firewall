grep -E 'reload_fail|rollback_fail|whitelist_cleared|bpf_tcp_in_empty' /var/log/firewalld-diag.log
curl -s http://127.0.0.1:9090/health | jq '.policy, .maps'