package session

import (
	"crypto/rand"
	"fmt"
	"sync"

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

func generateRandomBytes(num int) ([]byte, error) {
	bytes := make([]byte, num)
	num_gen, err := rand.Read(bytes)
	if err != nil || num_gen != num {
		return nil, err
	}
	return bytes, nil
}

func (m *SessionManager) CreateSession() (*uuid.UUID, error) {
	my_id := uuid.New()

	nonce, err := generateRandomBytes(16)
	if err != nil {
		return nil, err
	}
	session := Session{
		Id: my_id,
		Nonce: nonce,
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	m.sessions[my_id] = &session

	return &my_id, nil
}

func (m *SessionManager) GetSession(id *uuid.UUID) (*Session, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	session := m.sessions[*id]
	return session, nil
}

func (m *SessionManager) DelSession(id uuid.UUID) error {
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
	Nonce []byte `json:"nonce" binding:"required"`
	Id   uuid.UUID `json:"id" binding: "required"`
}

// GetID returns the ID of this session
func (s Session) GetID() uuid.UUID {
	return s.Id
}

