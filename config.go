package main

import (
	"github.com/kor44/freshCVE/cve"

	"io"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/pkg/errors"
)

type Config struct {
	Server struct {
		Address  string `hcl:"address"`
		Port     int    `hcl:"port"`
		Endpoint string `hcl:"endpoint"`
	} `hcl:"server"`

	Log struct {
		FileName string `hcl:"file"`
		Level    string `hcl:"level"`
	} `hcl:"log"`

	Timers struct {
		RequestTimeout      int `hcl:"request_timeout"`
		CacheUpdateInterval int `hcl:"cache_update_interval"`
	} `hcl:"timers"`

	SourcesTypes map[string]cve.SourceType `hcl:"sources_types"`
	Sources      map[string]cve.Source     `hcl:"sources"`
}

func readConfigFile(r io.Reader) (*Config, error) {
	cfg := &Config{}
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrapf(err, "Error to read config file")
	}

	//if err = hcl.Unmarshal(data, &cfg); err != nil {
	if err = hcl.Unmarshal(data, &cfg); err != nil {
		return nil, errors.Errorf("Error to parse config file: %s", err)
	}

	cfg.Timers.RequestTimeout = cfg.Timers.RequestTimeout
	cfg.Timers.CacheUpdateInterval = cfg.Timers.CacheUpdateInterval

	if cfg.Timers.RequestTimeout == 0 {
		cfg.Timers.RequestTimeout = 2
	}

	if cfg.Timers.CacheUpdateInterval == 0 {
		cfg.Timers.CacheUpdateInterval = 3600
	}

	if err = cve.ParseConfig(cfg.SourcesTypes, cfg.Sources); err != nil {
		err = errors.Wrap(err, "Error to read config file")
	}

	return cfg, err
}

/*func checkSourceAndTypes(conf *Config) error {
	// check all fields of type configuration is not empty
	for typeName, typeCfg := range conf.SourcesTypes {
		if typeCfg.ID == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'ID' parameter", typeName)
		}
		if typeCfg.Description == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'Description' parameter", typeName)
		}
		if typeCfg.Published == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'Published' parameter", typeName)
		}
		if typeCfg.References == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'References' parameter", typeName)
		}
	}

	// check that source configuration is correct
	for srcName, srcCfg := range conf.Sources {
		if conf.Sources[srcName].TypeName == "" {
			return errors.Errorf("Source '%s' configuration error. Need config  source type", srcName)
		}

		srcType, ok := conf.SourcesTypes[srcCfg.TypeName]
		if !ok {
			return errors.Errorf("Source '%s' configuration error. Unknown source type '%s'", srcName, srcCfg.TypeName)
		}
		srcCfg.Type = srcType
		conf.Sources[srcName] = srcCfg
	}

	return nil
}
*/
