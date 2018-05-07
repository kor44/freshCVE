package main

import (
	"flag"
	"fmt"
	"freshCVE/cve"
	"freshCVE/storage"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

func printHelp() {
	fmt.Fprintf(os.Stdout, "Usage of freshCVE:\n")
	flag.PrintDefaults()
}

func main() {
	var helpFlag bool
	var confFileName string
	var logFileName string
	var logLevel uint

	flag.BoolVar(&helpFlag, "help", false, "Print this help")
	flag.StringVar(&confFileName, "config", "", "Name of configuration file (required)")
	flag.StringVar(&logFileName, "logfile", "", "Name of log file. If empty output to stdout")
	flag.UintVar(&logLevel, "loglevel", 5, "Logging level: panic - 5, fatal - 4, error - 3, warn -2, info - 1, debug  - 0")
	flag.Parse()

	if helpFlag {
		printHelp()
		os.Exit(0)
	}

	if confFileName == "" {
		fmt.Fprint(os.Stderr, "Need specify name of configuration file\n")
		fmt.Fprintf(os.Stderr, "Usage of freshCVE:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	zerolog.SetGlobalLevel(zerolog.Level(logLevel))

	if logFileName == "" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal().Msgf("Unable to open log file '%s': %s", logFileName, err)
		}
		log.Logger = log.Output(logFile)
		defer logFile.Close()
	}

	// read config
	file, err := os.Open(confFileName)
	if err != nil {
		log.Fatal().Msgf("Unable to open config file: %s", err)
	}
	defer file.Close()

	conf, err := readConfigFile(file)
	if err != nil {
		log.Fatal().Msgf("Error to read config file: %#v", err)
	}

	// create server
	server := http.Server{Addr: ":8080"}

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

	http.HandleFunc("/api/v1/cves", apiHandler(db, conf))
	go updateCache(db, conf, exitServerCh)

	log.Info().Msg("Server start")
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
	log.Debug().Msg("updateData: started")
	defer log.Debug().Msg("updateData: stoped")
	ticker := time.NewTicker(conf.Timers.CacheUpdateInterval)
	for {
		select {
		case <-ticker.C:
			log.Debug().Msg("updateData: start get data")
			// здесь есть вероятность того, что пользователь не получит ничего
			// очищать нужно после того как получил все данные
			//db.Clear()
			//db.UpdateStart()
			getItems(db, conf)
			//db.UpdateEnd()

		case <-exit:
			log.Debug().Msg("updateData: received exit signal")
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
				Timeout: conf.Timers.RequestTimeout,
			}

			log.Debug().Msgf("Get data from source: %s", src.URL)
			resp, err := client.Get(src.URL)
			if err != nil {
				log.Error().Msgf("Failed to get data from source (%s): %s", src.URL, err)
				return
			}

			defer resp.Body.Close()

			d := json.NewDecoder(resp.Body)
			result := []map[string]interface{}{}
			if err := d.Decode(&result); err != nil {
				log.Error().Msgf("Failed to parse data from source (%s): %s", src.URL, err)
				return
			}

			items, _ := src.ParseData(result)
			db.AddData(items)
		}(src)
	}

	wg.Wait()
}
