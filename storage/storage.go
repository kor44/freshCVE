package storage

import (
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/kor44/freshCVE/cve"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func New() *Storage {
	return &Storage{
		data:  []cve.Item{},
		dataT: map[string]cve.Item{},
	}
}

// Storage is place where to store data.
type Storage struct {
	mu   sync.RWMutex
	data []cve.Item

	muT   sync.RWMutex
	dataT map[string]cve.Item

	updated bool
}

// Return current data
func (s *Storage) Data() []cve.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data
}

// Add items to storage
func (s *Storage) AddData(items []cve.Item) {
	log.Debug().Msgf("Cache: (updated: %t), add data %d", s.updated, len(items))

	s.muT.Lock()
	for _, item := range items {
		if _, ok := s.dataT[item.ID]; !ok {
			s.dataT[item.ID] = item
		}
	}
	s.muT.Unlock()
}

func (s *Storage) UpdateStart() {
	log.Debug().Msg("Cache: update start")
	s.updated = true
}

func (s *Storage) UpdateEnd() {
	log.Debug().Msg("Cache: update end")
	s.mu.Lock()
	s.muT.Lock()

	s.data = s.data[:0]
	for _, v := range s.dataT {
		s.data = append(s.data, v)
	}

	s.dataT = map[string]cve.Item{}

	s.updated = false
	s.mu.Unlock()
	s.muT.Unlock()
}

// Read cached data from file
func (s *Storage) ReadData(name string) error {
	log.Debug().Msgf("Cache: read data from file %s", name)
	file, err := os.Open(name)
	if err != nil {
		return errors.Wrap(err, "Error to open file with cached data")
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	data := []cve.Item{}
	if err := decoder.Decode(&data); err != nil && err != io.EOF {
		return errors.Wrap(err, "Unable to parse cache data from file")
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()

	return nil
}

// Save data to file
func (s *Storage) SaveData(name string) (err error) {
	file, err := os.Create(name)
	if err != nil {
		log.Debug().Msgf("Save error description: %v+", err)
		return errors.Wrap(err, "Error to open file with cached data")
	}

	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	encoder := json.NewEncoder(file)
	s.mu.RLock()
	err = encoder.Encode(s.data)
	s.mu.RUnlock()
	return err
}
