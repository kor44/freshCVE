package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/kor44/freshCVE/cve"
	"github.com/kor44/freshCVE/storage"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func printHelp() {
	fmt.Fprintf(os.Stdout, "Usage of freshCVE:\n")
	flag.PrintDefaults()
}

var (
	DefaultLoglevel = zerolog.InfoLevel.String()
	DefaultAddress  = ""
	DefaultPort     = 8080
	DefaultEndpoint = "/api/v1/cves"
)

func main() {
	// set log level to ErrorLevel to output if something goes wrong during init
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	var helpFlag bool
	var confFileName string
	var printConfig bool

	flag.BoolVar(&helpFlag, "help", false, "Print this help")
	flag.StringVar(&confFileName, "config", "", "Name of configuration file (required)")
	flag.BoolVar(&printConfig, "configPrint", false, "print default configuration")
	flag.Parse()

	if helpFlag {
		printHelp()
		os.Exit(0)
	}

	// print configuration to stdout
	if printConfig {
		fmt.Fprintf(os.Stdout, "%s", defaultConfig)
		os.Exit(0)
	}

	// check config option
	if confFileName == "" {
		fmt.Fprint(os.Stderr, "Need specify name of configuration file\n")
		fmt.Fprintf(os.Stderr, "Usage of freshCVE:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// read config
	file, err := os.Open(confFileName)
	if err != nil {
		log.Fatal().Msgf("Unable to open config file: %s", err)
		os.Exit(1)
	}
	defer file.Close()

	conf, err := readConfigFile(file)
	if err != nil {
		log.Fatal().Msgf("%s", err)
		os.Exit(1)
	}

	// log file configuration
	if conf.Log.FileName == "" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		logFile, err := os.OpenFile(conf.Log.FileName, os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal().Msgf("Unable to open log file '%s': %s", conf.Log.FileName, err)
		}
		log.Logger = log.Output(logFile)
		defer logFile.Close()
	}

	// log level configuration
	logLevels := map[string]zerolog.Level{
		"debug": zerolog.DebugLevel,
		"info":  zerolog.InfoLevel,
		"warn":  zerolog.WarnLevel,
		"error": zerolog.ErrorLevel,
		"fatal": zerolog.FatalLevel,
		"panic": zerolog.PanicLevel,
	}

	if conf.Log.Level == "" {
		conf.Log.Level = DefaultLoglevel
	}

	if _, ok := logLevels[conf.Log.Level]; !ok {
		log.Error().Msgf("Config file error: unknown log level '%s'", conf.Log.Level)
		conf.Log.Level = DefaultLoglevel
	}
	zerolog.SetGlobalLevel(logLevels[conf.Log.Level])

	// check server configuration
	if conf.Server.Port == 0 {
		conf.Server.Port = DefaultPort
	}

	if conf.Server.Endpoint == "" {
		conf.Server.Endpoint = "/api/v1/cves"
	}

	// create server
	server := http.Server{
		Addr: fmt.Sprintf("%s:%d", conf.Server.Address, conf.Server.Port),
	}

	exitServerCh := make(chan struct{})

	go func() {
		sigint := make(chan os.Signal)
		signal.Notify(sigint, os.Interrupt)
		signal.Notify(sigint, os.Kill)

		<-sigint

		//ctx, _ := context.WithTimeout(context.Background(), 2*conf.Timeout)
		if err := server.Shutdown(context.Background()); err != nil {
			log.Error().Msgf("Error to gracefully shutdown server: %s", err)
		}
		close(exitServerCh)
	}()

	db := storage.New()

	if err := db.ReadData("cache.db"); err != nil {
		log.Error().Msgf("Failed to read cache from disk: %s", err)
		getItems(db, conf)
	} else if len(db.Data()) == 0 {
		log.Debug().Msg("Saved cache is empty. Try to get data from sources")
		getItems(db, conf)
	}

	http.HandleFunc(conf.Server.Endpoint, apiHandler(db, conf))
	go updateCache(db, conf, exitServerCh)

	log.Info().Msgf("Server start: %s%s", server.Addr, conf.Server.Endpoint)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Msgf("Server process is failed: %s", err)
	}

	<-exitServerCh
	if err := db.SaveData("cache.db"); err != nil {
		log.Error().Msgf("Failed to save cache to disk: %s", err)
	}
	log.Info().Msg("Server exit")
}

func apiHandler(db *storage.Storage, conf *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		d := json.NewEncoder(w)
		d.Encode(db.Data())
	}
}

func updateCache(db *storage.Storage, conf *Config, exit <-chan struct{}) {
	log.Debug().Msg("updateCache routine: started")
	defer log.Debug().Msg("updateCache routine: stoped")
	ticker := time.NewTicker(time.Duration(conf.Timers.CacheUpdateInterval) * time.Second)
	for {
		select {
		case <-ticker.C:
			log.Debug().Msg("updateCache routine: start get data")
			db.UpdateStart()
			getItems(db, conf)
			db.UpdateEnd()
			log.Debug().Msg("updateCache routine: end get data")

		case <-exit:
			log.Debug().Msg("updateCache routine: received exit signal")
			return
		}
	}
}

func getItems(db *storage.Storage, conf *Config) {
	var wg sync.WaitGroup

	for _, src := range conf.Sources {
		wg.Add(1)

		go func(src cve.Source) {
			defer wg.Done()

			client := http.Client{
				Timeout: time.Duration(conf.Timers.RequestTimeout) * time.Second,
			}

			log.Debug().Msgf("getItems: get data from source %s", src.URL())
			resp, err := client.Get(src.URL())
			if err != nil {
				log.Error().Msgf("getItems: failed to get data from source %s. Error: %s", src.URL(), err)
				return
			}

			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				answer, _ := ioutil.ReadAll(resp.Body)
				log.Error().Msgf("getItems: source %s return error. Status: %s, details: %s",
					src.URL(), resp.Status, string(answer))
				return
			}

			d := json.NewDecoder(resp.Body)
			result := []map[string]interface{}{}
			if err := d.Decode(&result); err != nil {
				log.Error().Msgf("getItems: failed to parse data from source %s. Error: %s", src.URL(), err)
				return
			}

			items, _ := src.ParseData(result)
			db.AddData(items)
		}(src)
	}

	wg.Wait()
}
