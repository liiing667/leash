package macsync

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/messages"
)

// ClientState tracks connected macOS clients and their advertised capabilities.
type ClientState struct {
	ID string
	// ConnectionID is the connection-scoped websocket client id assigned by
	// the hub. It changes on every websocket reconnect, unlike ID which is the
	// stable identifier advertised by the macOS client itself.
	ConnectionID string
	// SessionID identifies the client's current logical sync session.
	SessionID    string
	Platform     string
	Capabilities map[string]bool
	Version      string
	LastSeen     time.Time
	Connected    bool
	// RuleGeneration is the highest rule-snapshot generation committed for
	// the client's current session.
	RuleGeneration uint64
}

// RuleSnapshot represents the latest macOS rule set delivered over the websocket.
type RuleSnapshot struct {
	FileRules    []messages.MacFileRule
	ExecRules    []messages.MacExecRule
	NetworkRules []messages.MacNetworkRule
	Version      string
	LastUpdate   time.Time
	// ClientID, SessionID and Generation bind the public snapshot to the
	// exact client connection transaction that produced it. A snapshot whose
	// session no longer owns the connection must never be applied to a new
	// session.
	ClientID   string
	SessionID  string
	Generation uint64
}

// StaleRuleSyncError indicates that a rule-sync transaction could not be
// committed because it was produced by a session that no longer owns the
// client connection or carried an out-of-date generation.
type StaleRuleSyncError struct {
	Reason     string
	ClientID   string
	SessionID  string
	Generation uint64
	// ServerGeneration is the generation currently committed on the daemon.
	ServerGeneration uint64
}

func (e *StaleRuleSyncError) Error() string {
	return fmt.Sprintf("macsync: stale rule sync rejected: %s (client=%s session=%s generation=%d server_generation=%d)",
		e.Reason, e.ClientID, e.SessionID, e.Generation, e.ServerGeneration)
}

// Manager centralises macOS-specific synchronisation data received over the websocket.
type Manager struct {
	mu      sync.RWMutex
	logger  *lsm.SharedLogger
	clients map[string]*ClientState
	// stableIndex maps a stable client id to its connection-scoped websocket id.
	stableIndex  map[string]string
	trackedPIDs  map[int]messages.MacTrackedPID
	rules        RuleSnapshot
	policyRules  map[string]messages.MacPolicyRule         // keyed by rule ID
	networkRules map[string]messages.MacNetworkRule        // keyed by rule ID
	policyEvents map[string]messages.MacPolicyEventPayload // keyed by event ID
	mitmConfig   *messages.MacMITMConfigPayload
	mitmSessions map[string]messages.MacMITMSessionPayload
	mitmVersion  int
	// sessionByClient records the logical session that currently owns each
	// stable client, so transactions from a dead session can be fenced off.
	sessionByClient map[string]string
}

// NewManager returns a macOS sync manager backed by the provided logger.
func NewManager(logger *lsm.SharedLogger) *Manager {
	return &Manager{
		logger:          logger,
		clients:         make(map[string]*ClientState),
		stableIndex:     make(map[string]string),
		trackedPIDs:     make(map[int]messages.MacTrackedPID),
		policyRules:     make(map[string]messages.MacPolicyRule),
		networkRules:    make(map[string]messages.MacNetworkRule),
		policyEvents:    make(map[string]messages.MacPolicyEventPayload),
		mitmSessions:    make(map[string]messages.MacMITMSessionPayload),
		sessionByClient: make(map[string]string),
	}
}

// RegisterClient records a new client hello payload. connectionID is the
// connection-scoped websocket id; the hello payload may additionally carry a
// stable client id and logical session id. When the same client reconnects in
// a new session, rule state owned by the previous session is invalidated so it
// can never be restored into the new session.
func (m *Manager) RegisterClient(connectionID string, payload *messages.ClientHelloPayload) {
	if payload == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	stableID := strings.TrimSpace(payload.ClientID)
	if stableID == "" {
		// Older clients don't advertise a stable id; fall back to the
		// connection-scoped id so binding semantics still apply.
		stableID = connectionID
	}
	sessionID := strings.TrimSpace(payload.SessionID)

	// Evict any state still attached to a previous connection of this client.
	if priorConn, ok := m.stableIndex[stableID]; ok && priorConn != connectionID {
		if _, exists := m.clients[priorConn]; exists {
			log.Printf("macsync: replacing stale connection %s for client %s with %s", priorConn, stableID, connectionID)
			delete(m.clients, priorConn)
		}
	}

	priorSession := m.sessionByClient[stableID]
	sessionRotated := sessionID != "" && priorSession != "" && priorSession != sessionID
	priorConn, known := m.stableIndex[stableID]
	reconnected := known && priorConn != connectionID
	// A reconnect (whether the logical session rotated or not) must never
	// start from the previous connection's rule state. Fence off any public
	// snapshot still owned by this client before the new session commits its
	// first transaction.
	if (reconnected || sessionRotated) && m.rules.ClientID == stableID {
		log.Printf("macsync: invalidating rule snapshot on reconnect of client %s (old_session=%s new_session=%s)",
			stableID, priorSession, sessionID)
		m.rules = RuleSnapshot{}
	}

	caps := make(map[string]bool, len(payload.Capabilities))
	for _, cap := range payload.Capabilities {
		caps[strings.ToLower(strings.TrimSpace(cap))] = true
	}

	m.clients[connectionID] = &ClientState{
		ID:           stableID,
		ConnectionID: connectionID,
		SessionID:    sessionID,
		Platform:     strings.ToLower(strings.TrimSpace(payload.Platform)),
		Capabilities: caps,
		Version:      payload.Version,
		LastSeen:     time.Now(),
		Connected:    true,
		// Generation restarts at zero for a freshly registered session; the
		// first committed snapshot must use generation >= 1.
		RuleGeneration: 0,
	}
	m.stableIndex[stableID] = connectionID
	if sessionID != "" {
		m.sessionByClient[stableID] = sessionID
	}

	log.Printf("macsync: registered client %s connection=%s session=%s platform=%s caps=%v",
		stableID, connectionID, sessionID, payload.Platform, payload.Capabilities)
}

// UnregisterClient marks a websocket connection as disconnected and removes
// its client state. Rule snapshots owned by the disconnected session are
// invalidated so they cannot be applied to a future session after reconnect.
func (m *Manager) UnregisterClient(connectionID string) {
	if connectionID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	client, ok := m.clients[connectionID]
	if !ok {
		return
	}
	delete(m.clients, connectionID)
	if m.stableIndex[client.ID] == connectionID {
		delete(m.stableIndex, client.ID)
	}

	if m.rules.ClientID == client.ID && m.rules.SessionID == client.SessionID {
		log.Printf("macsync: invalidating rule snapshot on disconnect of client %s session %s", client.ID, client.SessionID)
		m.rules = RuleSnapshot{}
	}

	log.Printf("macsync: unregistered client %s connection=%s session=%s", client.ID, connectionID, client.SessionID)
}

// GetAllClients returns a snapshot of all connected clients.
func (m *Manager) GetAllClients() []*ClientState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clients := make([]*ClientState, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients
}

// UpdateTrackedPIDs stores the latest tracked PIDs and returns the full snapshot for downstream use.
func (m *Manager) UpdateTrackedPIDs(clientID string, payload *messages.MacPIDSyncPayload) []messages.MacTrackedPID {
	if payload == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	next := make(map[int]messages.MacTrackedPID, len(payload.Entries))
	for _, entry := range payload.Entries {
		next[entry.PID] = entry
	}
	m.trackedPIDs = next

	if client := m.clients[clientID]; client != nil {
		client.LastSeen = time.Now()
	}

	out := make([]messages.MacTrackedPID, 0, len(m.trackedPIDs))
	for _, entry := range m.trackedPIDs {
		out = append(out, entry)
	}

	log.Printf("macsync: received %d tracked PIDs from %s (total %d)", len(payload.Entries), clientID, len(out))
	return out
}

// UpdateRules stores the last rule set received from a macOS client.
// The update is applied as a safe transaction: it must originate from the
// connection that currently owns the client, must target the client's current
// session, and must carry a generation strictly newer than the committed one.
// Rejected transactions leave all existing state untouched.
func (m *Manager) UpdateRules(connectionID string, payload *messages.MacRuleSyncPayload) (RuleSnapshot, error) {
	if payload == nil {
		return m.CurrentRules(), nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	client, ok := m.clients[connectionID]
	if !ok || !client.Connected {
		err := &StaleRuleSyncError{
			Reason:           "client connection is not registered",
			ClientID:         "",
			SessionID:        payload.SessionID,
			Generation:       payload.Generation,
			ServerGeneration: m.rules.Generation,
		}
		log.Printf("macsync: %v", err)
		return m.rules, err
	}

	// Bind the payload to the session that owns the live connection. Payloads
	// without an explicit session are accepted for legacy clients and treated
	// as belonging to the registered session.
	payloadSession := strings.TrimSpace(payload.SessionID)
	effectiveSession := client.SessionID
	if payloadSession != "" {
		if client.SessionID != "" && payloadSession != client.SessionID {
			err := &StaleRuleSyncError{
				Reason:           "payload session does not own the connection",
				ClientID:         client.ID,
				SessionID:        payloadSession,
				Generation:       payload.Generation,
				ServerGeneration: client.RuleGeneration,
			}
			log.Printf("macsync: %v", err)
			return m.rules, err
		}
		effectiveSession = payloadSession
	}

	generation := payload.Generation
	if generation == 0 {
		// Legacy clients don't track generations yet. Assign the next
		// server-side generation so their updates remain ordered and cannot
		// roll state backwards, while new clients enforce their own
		// monotonic counter transactionally.
		generation = client.RuleGeneration + 1
	} else if generation <= client.RuleGeneration {
		err := &StaleRuleSyncError{
			Reason:           "generation is not newer than committed generation",
			ClientID:         client.ID,
			SessionID:        effectiveSession,
			Generation:       generation,
			ServerGeneration: client.RuleGeneration,
		}
		log.Printf("macsync: %v", err)
		return m.rules, err
	}

	m.rules = RuleSnapshot{
		FileRules:    payload.FileRules,
		ExecRules:    payload.ExecRules,
		NetworkRules: payload.NetworkRules,
		Version:      payload.Version,
		LastUpdate:   time.Now(),
		ClientID:     client.ID,
		SessionID:    effectiveSession,
		Generation:   generation,
	}
	client.RuleGeneration = generation
	client.LastSeen = time.Now()

	log.Printf("macsync: committed rule transaction client=%s session=%s generation=%d file=%d exec=%d network=%d",
		client.ID, effectiveSession, generation, len(payload.FileRules), len(payload.ExecRules), len(payload.NetworkRules))
	return m.rules, nil
}

// CurrentTrackedPIDs returns the tracked PID snapshot.
func (m *Manager) CurrentTrackedPIDs() []messages.MacTrackedPID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]messages.MacTrackedPID, 0, len(m.trackedPIDs))
	for _, entry := range m.trackedPIDs {
		out = append(out, entry)
	}
	return out
}

// CurrentRules returns the last known rule snapshot.
func (m *Manager) CurrentRules() RuleSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules
}

// ClientSessionInfo describes the binding of a live client connection.
type ClientSessionInfo struct {
	StableID       string
	ConnectionID   string
	SessionID      string
	RuleGeneration uint64
	Connected      bool
}

// LookupClient returns the session binding for a connection-scoped client id.
func (m *Manager) LookupClient(connectionID string) (ClientSessionInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[connectionID]
	if !ok {
		return ClientSessionInfo{}, false
	}
	return ClientSessionInfo{
		StableID:       client.ID,
		ConnectionID:   client.ConnectionID,
		SessionID:      client.SessionID,
		RuleGeneration: client.RuleGeneration,
		Connected:      client.Connected,
	}, true
}

// PublicRuleSnapshot returns the committed rule snapshot together with its
// client/session/generation binding. The bool is false when no snapshot is
// committed or the snapshot belongs to a session that is no longer live, in
// which case callers must not advertise stale rule state to clients.
func (m *Manager) PublicRuleSnapshot() (RuleSnapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.rules.Generation == 0 && m.rules.LastUpdate.IsZero() {
		return RuleSnapshot{}, false
	}
	connID, ok := m.stableIndex[m.rules.ClientID]
	if !ok {
		return RuleSnapshot{}, false
	}
	client, ok := m.clients[connID]
	if !ok || !client.Connected || client.SessionID != m.rules.SessionID {
		return RuleSnapshot{}, false
	}
	return m.rules, true
}

// LogMacEvent converts mac-specific telemetry into the shared logger stream.
func (m *Manager) LogMacEvent(event *messages.MacEventPayload) error {
	if event == nil {
		return nil
	}

	if m.logger == nil {
		return fmt.Errorf("logger not configured")
	}

	ts := event.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	eventName := strings.TrimSpace(event.Event)
	if eventName == "" {
		eventName = "mac.telemetry"
	}

	fields := []string{
		fmt.Sprintf("time=%s", ts.Format(time.RFC3339)),
		fmt.Sprintf("event=%s", eventName),
	}

	detailMap := map[string]string{}
	if len(event.Details) > 0 {
		if err := json.Unmarshal(event.Details, &detailMap); err != nil {
			log.Printf("macsync: failed to decode mac event details: %v", err)
		}
	}

	kind := strings.TrimSpace(detailMap["kind"])
	if kind == "" {
		kind = strings.TrimPrefix(event.Event, "policy.")
	}

	switch {
	case eventName == "policy.processExec" || kind == "processExec":
		eventName = "proc.exec"
	case eventName == "policy.fileAccess" || kind == "fileAccess":
		op := strings.TrimSpace(detailMap["operation"])
		if op == "" {
			op = strings.TrimSpace(detailMap["file_operation"])
		}
		opLower := strings.ToLower(op)
		if opLower != "" {
			detailMap["operation"] = opLower
		}

		if strings.HasPrefix(eventName, "file.open:") {
			// Keep the existing subtype but normalize if it doesn't match the operation.
			switch opLower {
			case "create", "write":
				eventName = "file.open:rw"
			case "open", "read":
				eventName = "file.open:ro"
			default:
				// leave eventName as-is
			}
		} else {
			switch opLower {
			case "create", "write":
				eventName = "file.open:rw"
			case "open", "read":
				eventName = "file.open:ro"
			default:
				eventName = "file.open"
			}
		}
	}

	fields[1] = fmt.Sprintf("event=%s", eventName)

	if event.Event != "" {
		fields = append(fields, fmt.Sprintf("kind=%s", event.Event))
	}
	if event.Severity != "" {
		fields = append(fields, fmt.Sprintf("severity=%s", event.Severity))
	}
	if event.Source != "" {
		fields = append(fields, fmt.Sprintf("source=%q", event.Source))
	}
	if event.InstanceID != "" {
		fields = append(fields, fmt.Sprintf("instance=%q", event.InstanceID))
	}
	if event.RuleID != "" {
		fields = append(fields, fmt.Sprintf("rule_id=%q", event.RuleID))
	}

	decision := strings.ToLower(strings.TrimSpace(detailMap["decision"]))
	if decision == "" {
		switch {
		case strings.Contains(eventName, "deny"), strings.Contains(kind, "deny"), strings.EqualFold(detailMap["action"], "deny"):
			decision = "deny"
		default:
			decision = "allow"
		}
	}
	switch decision {
	case "deny", "denied", "block", "blocked":
		decision = "denied"
	case "allow", "allowed", "permit", "permitted":
		decision = "allowed"
	default:
		decision = "allowed"
	}
	fields = append(fields, fmt.Sprintf("decision=%s", decision))

	if pidStr := strings.TrimSpace(detailMap["pid"]); pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil {
			fields = append(fields, fmt.Sprintf("pid=%d", pid))
		}
	}
	if leashPIDStr := strings.TrimSpace(detailMap["leash_pid"]); leashPIDStr != "" {
		if leashPID, err := strconv.Atoi(leashPIDStr); err == nil {
			fields = append(fields, fmt.Sprintf("cgroup=%d", leashPID))
		}
	}
	if processPath := strings.TrimSpace(detailMap["process_path"]); processPath != "" {
		fields = append(fields, fmt.Sprintf("exe=%q", processPath))
	}
	if filePath := strings.TrimSpace(detailMap["file_path"]); filePath != "" {
		fields = append(fields, fmt.Sprintf("path=%q", filePath))
	}
	if cwd := strings.TrimSpace(detailMap["cwd"]); cwd != "" {
		fields = append(fields, fmt.Sprintf("cwd=%q", cwd))
	}
	if tty := strings.TrimSpace(detailMap["tty_path"]); tty != "" {
		fields = append(fields, fmt.Sprintf("tty=%q", tty))
	}
	if args := strings.TrimSpace(detailMap["args"]); args != "" {
		fields = append(fields, fmt.Sprintf("args=%q", args))
		if argcStr := strings.TrimSpace(detailMap["argc"]); argcStr != "" {
			if argc, err := strconv.Atoi(argcStr); err == nil {
				fields = append(fields, fmt.Sprintf("argc=%d", argc))
			}
		}
	}
	if operation := strings.TrimSpace(detailMap["operation"]); operation != "" {
		fields = append(fields, fmt.Sprintf("operation=%s", operation))
	}
	if dnsName := strings.TrimSpace(detailMap["hostname"]); dnsName != "" {
		fields = append(fields, fmt.Sprintf("hostname=%q", dnsName))
	}
	if resolved := strings.TrimSpace(detailMap["hostname_resolved"]); resolved != "" {
		fields = append(fields, fmt.Sprintf("hostname_resolved=%q", resolved))
	}
	if observed := strings.TrimSpace(detailMap["hostname_observed"]); observed != "" {
		fields = append(fields, fmt.Sprintf("hostname_observed=%q", observed))
	}
	if hostKind := strings.TrimSpace(detailMap["hostname_kind"]); hostKind != "" {
		fields = append(fields, fmt.Sprintf("hostname_kind=%s", hostKind))
	}
	if addr := strings.TrimSpace(detailMap["addr"]); addr != "" {
		fields = append(fields, fmt.Sprintf("addr=%q", addr))
	}
	if ip := strings.TrimSpace(detailMap["addr_ip"]); ip != "" {
		fields = append(fields, fmt.Sprintf("addr_ip=%q", ip))
	}
	if domain := strings.TrimSpace(detailMap["domain"]); domain != "" {
		fields = append(fields, fmt.Sprintf("domain=%q", domain))
	}
	if status := strings.TrimSpace(detailMap["status"]); status != "" {
		fields = append(fields, fmt.Sprintf("status=%s", status))
	}
	if port := strings.TrimSpace(detailMap["port"]); port != "" {
		fields = append(fields, fmt.Sprintf("port=%s", port))
	}
	if proto := strings.TrimSpace(detailMap["protocol"]); proto != "" {
		fields = append(fields, fmt.Sprintf("protocol=%s", strings.ToUpper(proto)))
	}
	if family := strings.TrimSpace(detailMap["family"]); family != "" {
		fields = append(fields, fmt.Sprintf("family=%s", family))
	}
	if parent := strings.TrimSpace(detailMap["parent_process"]); parent != "" {
		fields = append(fields, fmt.Sprintf("parent=%q", parent))
	}
	if leashProcess := strings.TrimSpace(detailMap["leash_process"]); leashProcess != "" {
		fields = append(fields, fmt.Sprintf("session=%q", leashProcess))
	}
	if leashArgs := strings.TrimSpace(detailMap["leash_args"]); leashArgs != "" {
		fields = append(fields, fmt.Sprintf("session_args=%q", leashArgs))
	}
	if leashTTY := strings.TrimSpace(detailMap["leash_tty"]); leashTTY != "" {
		fields = append(fields, fmt.Sprintf("session_tty=%q", leashTTY))
	}
	if reason := strings.TrimSpace(detailMap["reason"]); reason != "" {
		fields = append(fields, fmt.Sprintf("reason=%q", reason))
	}

	entry := strings.Join(fields, " ")
	return m.logger.Write(entry)
}

// MARK: - Policy Events & Decisions

// StorePolicyEvent stores a policy event for later decision matching.
func (m *Manager) StorePolicyEvent(event *messages.MacPolicyEventPayload) {
	if event == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policyEvents[event.ID] = *event
	log.Printf("macsync: stored policy event %s kind=%s process=%s", event.ID, event.Kind, event.ProcessPath)
}

// ProcessPolicyDecision converts a decision into a rule and stores it.
func (m *Manager) ProcessPolicyDecision(decision *messages.MacPolicyDecisionPayload) error {
	if decision == nil {
		return fmt.Errorf("decision payload required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	event, exists := m.policyEvents[decision.EventID]
	if !exists {
		return fmt.Errorf("event %s not found", decision.EventID)
	}

	// Only create persistent rules for "always" and "directory" scopes
	if decision.Scope.Type != "always" && decision.Scope.Type != "directory" {
		// For "once" scope, just allow/deny without creating a rule
		delete(m.policyEvents, decision.EventID)
		return nil
	}

	// Create a rule from the decision
	rule := messages.MacPolicyRule{
		ID:             fmt.Sprintf("%s-%s", event.ID[:8], decision.Action),
		Kind:           event.Kind,
		Action:         decision.Action,
		ExecutablePath: event.ProcessPath,
	}

	if event.FileOperation == "create" || event.FileOperation == "write" {
		rule.CoversCreates = true
	}

	if decision.Scope.Type == "directory" && decision.Scope.Path != "" {
		rule.Directory = decision.Scope.Path
	} else if event.CurrentWorkingDirectory != "" {
		rule.Directory = event.CurrentWorkingDirectory
	}

	if event.FilePath != "" {
		rule.FilePath = event.FilePath
	}

	m.policyRules[rule.ID] = rule
	delete(m.policyEvents, decision.EventID)

	log.Printf("macsync: created policy rule %s: %s %s → %s", rule.ID, rule.Action, rule.ExecutablePath, rule.Kind)
	return nil
}

// MARK: - Policy Rules

// GetPolicyRules returns all current policy rules.
func (m *Manager) GetPolicyRules() []messages.MacPolicyRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]messages.MacPolicyRule, 0, len(m.policyRules))
	for _, rule := range m.policyRules {
		rules = append(rules, rule)
	}
	return rules
}

// AddPolicyRules adds new policy rules.
func (m *Manager) AddPolicyRules(rules []messages.MacPolicyRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rule := range rules {
		m.policyRules[rule.ID] = rule
		log.Printf("macsync: added policy rule %s: %s %s", rule.ID, rule.Action, rule.ExecutablePath)
	}
}

// RemovePolicyRules removes rules by ID.
func (m *Manager) RemovePolicyRules(ids []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, id := range ids {
		if _, exists := m.policyRules[id]; exists {
			delete(m.policyRules, id)
			log.Printf("macsync: removed policy rule %s", id)
		}
	}
}

// ClearPolicyRules removes all policy rules.
func (m *Manager) ClearPolicyRules() {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := len(m.policyRules)
	m.policyRules = make(map[string]messages.MacPolicyRule)
	log.Printf("macsync: cleared %d policy rules", count)
}

// MARK: - Network Rules

// GetNetworkRules returns all current network rules.
func (m *Manager) GetNetworkRules() []messages.MacNetworkRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]messages.MacNetworkRule, 0, len(m.networkRules))
	for _, rule := range m.networkRules {
		rules = append(rules, rule)
	}
	return rules
}

// UpdateNetworkRules replaces all network rules.
func (m *Manager) UpdateNetworkRules(rules []messages.MacNetworkRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.networkRules = make(map[string]messages.MacNetworkRule, len(rules))
	for _, rule := range rules {
		m.networkRules[rule.ID] = rule
	}

	enabledCount := 0
	for _, rule := range rules {
		if rule.Enabled {
			enabledCount++
		}
	}

	log.Printf("macsync: updated network rules: %d total, %d enabled", len(rules), enabledCount)
}

// MARK: - MITM State

// SetMITMConfig stores the latest MITM configuration payload.
func (m *Manager) SetMITMConfig(cfg *messages.MacMITMConfigPayload) {
	if cfg == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.mitmConfig = cfg
	if cfg.Version > 0 {
		m.mitmVersion = cfg.Version
	}

	log.Printf("macsync: updated MITM config (enabled=%v listen=%s version=%d)", cfg.Enabled, cfg.ListenAddress, cfg.Version)
}

// CurrentMITMConfig returns a copy of the most recent MITM configuration.
func (m *Manager) CurrentMITMConfig() *messages.MacMITMConfigPayload {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mitmConfig == nil {
		return nil
	}

	cfg := *m.mitmConfig
	if cfg.Version == 0 {
		cfg.Version = m.mitmVersion
	}
	return &cfg
}

// UpsertMITMSession records a session lifecycle update.
func (m *Manager) UpsertMITMSession(session messages.MacMITMSessionPayload) {
	if session.SessionID == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch strings.ToLower(session.Action) {
	case "stop", "delete":
		delete(m.mitmSessions, session.SessionID)
		log.Printf("macsync: removed MITM session %s", session.SessionID)
	default:
		m.mitmSessions[session.SessionID] = session
		log.Printf("macsync: upserted MITM session %s action=%s leash_pid=%d", session.SessionID, session.Action, session.LeashPID)
	}
}

// RemoveMITMSession removes a session by ID.
func (m *Manager) RemoveMITMSession(sessionID string) {
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mitmSessions, sessionID)
	log.Printf("macsync: removed MITM session %s", sessionID)
}

// CurrentMITMSessions returns all known sessions.
func (m *Manager) CurrentMITMSessions() []messages.MacMITMSessionPayload {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]messages.MacMITMSessionPayload, 0, len(m.mitmSessions))
	for _, sess := range m.mitmSessions {
		sessions = append(sessions, sess)
	}
	return sessions
}
