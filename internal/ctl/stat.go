package ctl

import (
	"fmt"

	"github.com/huzenkon/waf-firewall/internal/config"
)

func Stat(cfg *config.Config) (StatInfo, error) {
	active, err := isServiceActive()
	if err != nil {
		return StatInfo{}, err
	}
	if !active {
		return StatInfo{Active: false}, nil
	}
	stats, err := fetchDaemonStats(cfg)
	if err != nil {
		return StatInfo{}, err
	}
	return StatInfo{Active: true, Stats: stats}, nil
}

func fetchDaemonStats(cfg *config.Config) (PacketStats, error) {
	health, err := fetchDaemonHealth(cfg)
	if err != nil {
		return PacketStats{}, err
	}
	if health.Stats == nil {
		return PacketStats{}, fmt.Errorf("daemon health: stats unavailable")
	}
	return *health.Stats, nil
}
