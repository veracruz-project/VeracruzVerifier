// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package session

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/veraison/services/verification/sessionmanager"
)

type SessionManager struct {
	lock     *sync.Mutex // protects session
	sessions map[uuid.UUID]*Session
}

func NewSessionManager() *SessionManager {
	manager := &SessionManager{}
	manager.sessions = make(map[uuid.UUID]*Session)
	manager.lock = new(sync.Mutex)
	return manager
}

func (m *SessionManager) Init(cfg sessionmanager.Config) error {
	return nil
}

func (m *SessionManager) SetSession(id uuid.UUID, tenant string, sessionData json.RawMessage, ttl time.Duration) error {
	  
	  
	var data SessionInfo
	json.Unmarshal([]byte(sessionData), &data)
	fmt.Printf("SetSession with Nonce: %v, Expiry: %v, Accept:%v, State:%v", data.Nonce, data.Expiry, data.Accept, data.State)
	session := Session{}
	session.Nonce = data.Nonce
	expiry := time.Now().Add(time.Second * ttl)
	session.Init(id, data.Nonce, expiry)

	m.lock.Lock()
	defer m.lock.Unlock()
	m.sessions[session.GetID()] = &session

	return nil
}

func (m *SessionManager) GetSession(id uuid.UUID, tenant string) (json.RawMessage, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	session := m.sessions[id]
	json_data, err := json.Marshal(session)
	if err != nil {
		fmt.Println("SessionManager::GetSession failed to Marshal: %e", err)
		return nil, err
	}
	return json_data, nil
}

func (m *SessionManager) DelSession(id uuid.UUID, tenant string) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return fmt.Errorf("session with id \"%d\" does not exist", id)
	}

	delete(m.sessions, id)
	return nil
}

func (m *SessionManager) Close() error {
	return nil
}

type Session struct {
	SessionInfo
	id   uuid.UUID
	data map[interface{}]interface{}
}

type SessionInfo struct {
	Nonce  []byte    `json:"nonce" binding:"required"`
	Expiry time.Time `json:"expiry" binding:"required"`
	Accept []string  `json:"accept" binding:"required"`
	State  string    `json:"state" binding:"required"`
}

// Init initializes a new session with the specified ID
func (s *Session) Init(id uuid.UUID, nonce []byte, expiry time.Time) {
	s.Nonce = nonce
	s.Expiry = expiry
	s.Accept = []string{ // TODO: should not be hard-coded
		"application/psa-attestation-token",
	}
	s.State = "waiting"
	s.id = id
	s.data = make(map[interface{}]interface{})
}

// GetID returns the ID of this session
func (s Session) GetID() uuid.UUID {
	return s.id
}

