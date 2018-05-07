package main

import (
	"freshCVE/cve"

	"encoding/json"
	"io"
	"time"
)

type Config struct {
	Server struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	} `json:"server"`

	// Path to log file. If empty output to stdout
	LogFile string `json:"log_file"`

	Timers struct {
		RequestTimeout      time.Duration `json:"request_timeout"`
		CacheUpdateInterval time.Duration `json:"cache_update_interval"`
	} `json:"timers"`

	SourcesTypes map[string]interface{} `json:"sources_types"`
	SourcesList  []map[string]string    `json:"sources"`

	Sources []cve.Source `json:"-"`
}

func (cfg *Config) asdfaf() {

}

func readConfigFile(r io.Reader) (*Config, error) {
	cfg := &Config{}
	dec := json.NewDecoder(r)
	err := dec.Decode(cfg)

	cfg.Timers.RequestTimeout = cfg.Timers.RequestTimeout * time.Second
	cfg.Timers.CacheUpdateInterval = cfg.Timers.CacheUpdateInterval * time.Second

	if cfg.Timers.RequestTimeout == 0 {
		cfg.Timers.RequestTimeout = 2 * time.Second
	}

	if cfg.Timers.CacheUpdateInterval == 0 {
		cfg.Timers.CacheUpdateInterval = 3600 * time.Second
	}

	cfg.Sources, err = cve.ParseSourcesCfg(cfg.SourcesTypes, cfg.SourcesList)

	return cfg, err
}

var confTempl = `
{
	"server": {
		"address": "",
		"port": 8080
	},
	"timers": {
		"request_timeout": 2,
		"cache_update_interval": 60
	},
	"sources_types": {
		"circl": {
			"ID": "id",
			"Published": "Published",
			"References": "references",
			"Description": "summary"
		},
		"redhat": {
			"ID": "CVE",
			"Published": "public_date",
			"References": "resource_url",
			"Description": "bugzilla_description"
		}
	},
	"sources": [
		{
			"name": "circle source (last two days)",
			"url": "http://cve.circl.lu/api/last/2",
			"type": "circl"
		},
		{
			"name": "redhat source",
			"url": "http://access.redhat.com/labs/securitydataapi/cve.json?after=2018-04-25",
			"type": "redhat"
		}
	]
}
`
