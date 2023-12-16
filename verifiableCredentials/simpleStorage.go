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
	if vc.Proof == nil {
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

	err = os.MkdirAll(filepath.Dir(absPath), os.ModePerm)
	if err != nil {
		return errors.Join(errors.New("ToFile error on creating dirs: "), err)
	}
	file, err := os.Create(filepath.Join(filepath.Dir(absPath), filepath.Base(absPath)))
	if err != nil {
		return errors.Join(errors.New("ToFile error on creating file: "), err)
	}
	defer func() {
		er := file.Close()
		if er != nil {
			err = errors.Join(err, er)
		}
	}()

	var vcList []*VerifiableCredential

	for _, vc := range s.vc {
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
		/*
			vcj, err = jwe.Decrypt(vcj, jwe.WithKey(jwa.RSA1_5, key))
			if err != nil {
				return nil, err
			}

		*/
	}

	var vcList []*VerifiableCredential

	err = json.Unmarshal(vcj, &vcList)
	if err != nil {
		return nil, err
	}

	store := NewStore()

	for _, vc := range vcList {
		err := store.Create(vc)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}
