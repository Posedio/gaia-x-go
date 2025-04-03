/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package verifiableCredentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Store struct {
	vc       map[string]*VerifiableCredential
	mux      sync.RWMutex
	validate *validator.Validate
}

func NewStore() *Store {
	return &Store{
		vc:       make(map[string]*VerifiableCredential),
		validate: validator.New(),
	}
}

func (s *Store) Create(vc *VerifiableCredential) error {
	s.mux.RLock()
	if _, k := s.vc[vc.ID]; k {
		s.mux.RUnlock()
		return errors.New("vc already exists")
	}
	s.mux.RUnlock()

	err := s.validate.Struct(vc)
	if err != nil {
		return err
	}
	if vc.Proof == nil && vc.signature == nil {
		return errors.New("vc needs a proof")
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	s.vc[vc.ID] = vc
	return nil
}

func (s *Store) Update(vc *VerifiableCredential) error {
	s.mux.RLock()
	if _, k := s.vc[vc.ID]; !k {
		s.mux.RUnlock()
		return errors.New("vc does not exists")
	}
	s.mux.RUnlock()

	err := s.validate.Struct(vc)
	if err != nil {
		return err
	}
	if vc.Proof == nil {
		return errors.New("vc needs a proof")
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	s.vc[vc.ID] = vc
	return nil
}

func (s *Store) Delete(id string) {
	s.mux.Lock()
	defer s.mux.RUnlock()
	delete(s.vc, id)
}

func (s *Store) Read(id string) (*VerifiableCredential, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()
	if vc, k := s.vc[id]; k {
		return vc, nil
	}
	return nil, fmt.Errorf("id %v does not store", id)
}

func (s *Store) GetAllIndex() []string {
	s.mux.RLock()
	defer s.mux.RUnlock()

	var index []string

	for ele := range s.vc {
		index = append(index, ele)
	}
	sort.Strings(index)
	return index
}

func (s *Store) ToFile(path string, keyPhrase []byte) (err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return errors.Join(errors.New("ToFile error on absolute file path: "), err)
	}

	err = os.MkdirAll(filepath.Dir(absPath), os.ModeDir)
	if err != nil {
		return errors.Join(errors.New("ToFile error on creating dirs: "), err)
	}
	file, err := os.Create(filepath.Join(filepath.Dir(absPath), filepath.Base(absPath)))
	if err != nil {
		return errors.Join(errors.New("ToFile error on creating file: "), err)
	}
	defer func() {
		_ = file.Close()
	}()

	var vcList []any

	for _, vc := range s.vc {
		if vc.Proof != nil {
			vcList = append(vcList, vc)
			continue
		} else if vc.signature != nil {
			a := vc.GetOriginalJWS()
			if a != nil && len(a) > 0 {
				vcList = append(vcList, string(a))
				continue
			}
		}
		//unsigned
		vcList = append(vcList, vc)

	}

	marshal, err := json.Marshal(vcList)
	if err != nil {
		return err
	}
	if keyPhrase != nil {
		cb, err := aes.NewCipher(keyPhrase)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(cb)
		if err != nil {
			return err
		}
		nonce := make([]byte, gcm.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			return err
		}

		marshal = gcm.Seal(nonce, nonce, marshal, nil)
	}
	_, err = file.Write(marshal)
	if err != nil {
		return err
	}

	return nil
}

func NewStoreFromFile(path string, keyPhrase []byte) (s *Store, err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.Join(errors.New("NewStoreFromFile error on absolute file path: "), err)
	}

	vcj, err := os.ReadFile(filepath.Clean(absPath))
	if err != nil {
		return nil, err
	}

	if keyPhrase != nil {
		cb, err := aes.NewCipher(keyPhrase)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(cb)
		if err != nil {
			return nil, err
		}

		nonceSize := gcm.NonceSize()
		if len(vcj) < nonceSize {
			return nil, err
		}

		nonce, ciphertext := vcj[:nonceSize], vcj[nonceSize:]
		vcj, err = gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	}

	var vcList []any
	store := NewStore()

	err = json.Unmarshal(vcj, &vcList)
	if err != nil {
		return nil, err
	}

	log.Println(vcList)

	for _, vc := range vcList {
		switch vc.(type) {
		case map[string]interface{}:
			vj, err := json.Marshal(vc.(map[string]interface{}))
			if err != nil {
				return nil, err
			}
			v := NewEmptyVerifiableCredential()
			err = json.Unmarshal(vj, v)
			if err != nil {
				return nil, err
			}
			err = store.Create(v)
			if err != nil {
				return nil, err
			}
		case string:
			v, err := VCFromJWT([]byte(vc.(string)))
			if err != nil {
				return nil, err
			}
			err = store.Create(v)
			if err != nil {
				return nil, err
			}
		}

	}

	return store, nil
}
