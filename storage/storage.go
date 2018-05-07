package storage

import (
	"encoding/json"
	"freshCVE/cve"
	"io"
	"os"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/pkg/errors"
)

func New() *Storage {
	return &Storage{
		//ids:  map[string]bool{},
		data: map[string]cve.Item{},

		//idsT:  map[string]bool{},
		dataT: map[string]cve.Item{},
	}
}

// Storage is place where to store data.
type Storage struct {
	mu sync.RWMutex
	//ids  map[string]bool
	//data []cve.Item
	data map[string]cve.Item

	updated bool

	muT sync.RWMutex
	//idsT  map[string]bool
	//dataT []cve.Item
	dataT map[string]cve.Item
}

// Return current data
func (s *Storage) Data() []cve.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var i int
	result := make([]cve.Item, len(s.data))
	for _, v := range s.data {
		result[i] = v
		i++
	}

	return result
}

// Add items to storage
func (s *Storage) AddData(items []cve.Item) {
	if s.updated {

	} else {
		s.mu.Lock()
		for _, item := range items {
			if _, ok := s.data[item.ID]; !ok {
				s.data[item.ID] = item
			}
		}

		s.mu.Unlock()
	}

}

//func (s *Storage) addData(items []cve.Item) {
//	s.mu.Lock()
//	for _, item := range items {
//		if ok := s.ids[item.ID]; !ok {
//			s.ids[item.ID] = true
//			s.data = append(s.data, item)
//		}
//	}

//	s.mu.Unlock()
//}

func (s *Storage) UpdateStart() {
	s.updated = true

}

func (s *Storage) UpdateEnd() {
	s.mu.Lock()
	s.muT.Lock()

	s.data = s.dataT
	s.dataT = map[string]cve.Item{}

	s.mu.Unlock()
	s.muT.Unlock()

	s.updated = false
}

// Remove all data from storage
func (s *Storage) Clear() {
	s.mu.Lock()
	s.data = map[string]cve.Item{}
	s.mu.Unlock()
}

// Read cached data from file
func (s *Storage) ReadData(name string) error {
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
	s.Clear()
	s.AddData(data)

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
	err = encoder.Encode(s.Data())
	s.mu.RUnlock()
	return err
}
