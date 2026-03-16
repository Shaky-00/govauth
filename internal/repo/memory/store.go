package memory

import (
	"fmt"
	"sync"

	"govauth/internal/domain/model"
)

// Store 是一个最小可运行的内存仓库。
// 当前版本不接数据库，所有对象都保存在内存中，便于快速验证 happy path。
type Store struct {
	mu          sync.RWMutex
	policies    map[string]*model.Policy
	plans       map[string]*model.EnforcementPlan
	sessions    map[string]*model.ExecutionSession
	evidences   map[string]*model.EvidenceRecord
	snapshots   map[string]*model.PinnedSnapshot
	evaluations map[string]*model.EvaluationResult
	artifacts   map[string]*model.AuthorizationArtifact
	events      []*model.TransitionEvent
}

// NewStore 创建一个空内存仓库。
func NewStore() *Store {
	return &Store{
		policies:    make(map[string]*model.Policy),
		plans:       make(map[string]*model.EnforcementPlan),
		sessions:    make(map[string]*model.ExecutionSession),
		evidences:   make(map[string]*model.EvidenceRecord),
		snapshots:   make(map[string]*model.PinnedSnapshot),
		evaluations: make(map[string]*model.EvaluationResult),
		artifacts:   make(map[string]*model.AuthorizationArtifact),
		events:      make([]*model.TransitionEvent, 0),
	}
}

func (s *Store) SavePolicy(p *model.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
}

func (s *Store) GetPolicy(id string) (*model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return p, nil
}

func (s *Store) SavePlan(p *model.EnforcementPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans[p.ID] = p
}

func (s *Store) GetPlan(id string) (*model.EnforcementPlan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.plans[id]
	if !ok {
		return nil, fmt.Errorf("plan not found: %s", id)
	}
	return p, nil
}

func (s *Store) SaveSession(sess *model.ExecutionSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

func (s *Store) GetSession(id string) (*model.ExecutionSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}
	return sess, nil
}

func (s *Store) SaveEvidence(e *model.EvidenceRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evidences[e.ID] = e
}

func (s *Store) GetEvidence(id string) (*model.EvidenceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.evidences[id]
	if !ok {
		return nil, fmt.Errorf("evidence not found: %s", id)
	}
	return e, nil
}

func (s *Store) SaveSnapshot(snapshot *model.PinnedSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[snapshot.ID] = snapshot
}

func (s *Store) GetSnapshot(id string) (*model.PinnedSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, ok := s.snapshots[id]
	if !ok {
		return nil, fmt.Errorf("snapshot not found: %s", id)
	}
	return snapshot, nil
}

func (s *Store) SaveEvaluation(e *model.EvaluationResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evaluations[e.ID] = e
}

func (s *Store) GetEvaluation(id string) (*model.EvaluationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.evaluations[id]
	if !ok {
		return nil, fmt.Errorf("evaluation not found: %s", id)
	}
	return e, nil
}

func (s *Store) SaveArtifact(a *model.AuthorizationArtifact) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[a.ID] = a
}

func (s *Store) GetArtifact(id string) (*model.AuthorizationArtifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.artifacts[id]
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", id)
	}
	return a, nil
}

func (s *Store) AppendEvent(event *model.TransitionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *Store) ListEvents(sessionID, policyID string) []*model.TransitionEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*model.TransitionEvent, 0)
	for _, event := range s.events {
		if sessionID != "" && event.SessionID == sessionID {
			result = append(result, event)
			continue
		}
		if policyID != "" && event.PolicyID == policyID {
			result = append(result, event)
		}
	}
	return result
}
