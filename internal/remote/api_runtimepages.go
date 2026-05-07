package remote

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulpineos/internal/juggler"
	"vulpineos/internal/scripting"
	"vulpineos/internal/security"
)

const (
	maxPanelScriptBytes = 64 * 1024
	maxPanelScriptSteps = 100
)

type securityProtection struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Details     string `json:"details,omitempty"`
}

type SecurityScanner struct {
	mu         sync.Mutex
	LastScan   *securityScanResult `json:"lastScan,omitempty"`
	KillSwitch *securityKillResult `json:"killSwitch,omitempty"`
}

type securityScanResult struct {
	OK             bool                `json:"ok"`
	Status         string              `json:"status"`
	ContextID      string              `json:"contextId,omitempty"`
	SessionID      string              `json:"sessionId,omitempty"`
	URL            string              `json:"url,omitempty"`
	Title          string              `json:"title,omitempty"`
	RiskScore      float64             `json:"riskScore"`
	Clean          bool                `json:"clean"`
	MatchCount     int                 `json:"matchCount"`
	Matches        []securityScanMatch `json:"matches"`
	ScannedBytes   int                 `json:"scannedBytes"`
	Threshold      float64             `json:"threshold"`
	KillOnRisk     bool                `json:"killOnRisk"`
	KillSwitch     *securityKillResult `json:"killSwitch,omitempty"`
	SignatureCount int                 `json:"signatureCount"`
	ScannedAt      time.Time           `json:"scannedAt"`
	Error          string              `json:"error,omitempty"`
}

type securityScanMatch struct {
	Pattern  string `json:"pattern"`
	Content  string `json:"content"`
	Severity int    `json:"severity"`
	Position int    `json:"position"`
}

type securityKillResult struct {
	Activated      bool      `json:"activated"`
	Reason         string    `json:"reason"`
	KilledAgents   int       `json:"killedAgents"`
	BrowserStopped bool      `json:"browserStopped"`
	TriggeredAt    time.Time `json:"triggeredAt"`
	Error          string    `json:"error,omitempty"`
}

type securityPageSnapshot struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Text  string `json:"text"`
	HTML  string `json:"html"`
}

type optimizedDOMSnapshot struct {
	Title string          `json:"title"`
	URL   string          `json:"url"`
	Nodes json.RawMessage `json:"nodes"`
}

var securitySnippetSecretPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|token|access[_-]?token|access[_-]?key|secret|password|credential|authorization|cookie|session)\s*[=:]\s*[^,\s;'"<>]+`)

func (api *PanelAPI) scriptsRun(params json.RawMessage) (json.RawMessage, error) {
	if api.Client == nil {
		return nil, fmt.Errorf("juggler client not available")
	}
	var p struct {
		Script    string `json:"script"`
		ContextID string `json:"contextId"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	p.Script = strings.TrimSpace(p.Script)
	if p.Script == "" {
		return nil, fmt.Errorf("script is required")
	}
	if len(p.Script) > maxPanelScriptBytes {
		return nil, fmt.Errorf("script exceeds %d byte limit", maxPanelScriptBytes)
	}

	script, err := scripting.ParseScript([]byte(p.Script))
	if err != nil {
		return nil, err
	}
	if len(script.Steps) > maxPanelScriptSteps {
		return nil, fmt.Errorf("script has %d steps; maximum is %d", len(script.Steps), maxPanelScriptSteps)
	}

	contextID, sessionID, err := api.ensureScriptSession(p.ContextID)
	if err != nil {
		return nil, err
	}

	engine := scripting.NewEngine(api.Client)
	engine.SetSession(sessionID)
	results, runErr := engine.ExecuteWithResults(script)
	payload := map[string]interface{}{
		"ok":        runErr == nil,
		"contextId": contextID,
		"sessionId": sessionID,
		"results":   results,
		"vars":      engine.RedactedVars(),
	}
	if runErr != nil {
		payload["error"] = runErr.Error()
	}
	return json.Marshal(payload)
}

func (api *PanelAPI) securityStatus() (json.RawMessage, error) {
	browserActive := api.Client != nil && api.Kernel != nil && api.Kernel.Running()
	securityEnabled := api.Orchestrator != nil && api.Orchestrator.SecurityEnabled
	signatureDB := security.NewSignatureDB()
	sandbox := security.NewSandbox()
	scanner := api.securityScanner().Snapshot()

	protections := []securityProtection{
		{
			Key:         "ax_filter",
			Name:        "Injection-Proof AX Filter",
			Description: "Strips hidden DOM nodes before AI-readable accessibility output.",
			Status:      ternaryStatus(browserActive, "active", "disabled"),
			Details:     "Backed by the Camoufox accessibility filter pref.",
		},
		{
			Key:         "action_lock",
			Name:        "Action-Lock",
			Description: "Freezes the page while the agent is reasoning.",
			Status:      ternaryStatus(browserActive, "active", "disabled"),
			Details:     "Backed by the patched nsDocShell suspend/resume path.",
		},
		{
			Key:         "csp",
			Name:        "CSP Header Injection",
			Description: "Injects restrictive Content-Security-Policy headers on secured contexts.",
			Status:      ternaryStatus(browserActive && securityEnabled, "active", "disabled"),
			Details:     ternaryText(securityEnabled, "Enabled for orchestrator-managed contexts.", "Security suite is not enabled for new orchestrator contexts."),
		},
		{
			Key:         "mutations",
			Name:        "DOM Mutation Monitor",
			Description: "Detects suspicious elements injected after load.",
			Status:      ternaryStatus(browserActive, "available", "disabled"),
			Details:     "Observer implementation exists, but the orchestrator does not auto-inject it yet.",
		},
		{
			Key:         "signatures",
			Name:        "Injection Signature Scanner",
			Description: "Scans page text for known prompt-injection patterns.",
			Status:      "available",
			Details:     fmt.Sprintf("%d signatures loaded; manual panel scanner available.", signatureDB.Count()),
		},
		{
			Key:         "sandbox",
			Name:        "Sandboxed JS Evaluation",
			Description: "Wraps JS evaluation with blocked network-capable APIs.",
			Status:      "available",
			Details:     fmt.Sprintf("Blocked APIs: %s.", joinStrings(sandbox.BlockedAPIs(), ", ")),
		},
		{
			Key:         "optimized_dom",
			Name:        "Token-Optimized DOM",
			Description: "Compressed DOM export optimized for model context windows.",
			Status:      ternaryStatus(browserActive, "active", "disabled"),
			Details:     "Available through the browser protocol and MCP toolchain.",
		},
	}

	return json.Marshal(map[string]interface{}{
		"browserActive":         browserActive,
		"securityEnabled":       securityEnabled,
		"signaturePatternCount": signatureDB.Count(),
		"sandboxBlockedAPIs":    sandbox.BlockedAPIs(),
		"scanner":               scanner,
		"protections":           protections,
	})
}

func (api *PanelAPI) securityScan(params json.RawMessage) (json.RawMessage, error) {
	if api.Client == nil {
		return nil, fmt.Errorf("juggler client not available")
	}
	var p struct {
		ContextID  string  `json:"contextId"`
		KillOnRisk bool    `json:"killOnRisk"`
		Threshold  float64 `json:"threshold"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	if p.Threshold <= 0 {
		p.Threshold = 0.7
	} else if p.Threshold > 1 {
		p.Threshold = 1
	}

	contextID, sessionID, err := api.ensureScriptSession(p.ContextID)
	if err != nil {
		return nil, err
	}
	page, err := api.readSecurityScanPage(sessionID)
	if err != nil {
		return nil, err
	}

	db := security.NewSignatureDB()
	scanned := page.HTML
	if page.Text != "" {
		scanned += "\n" + page.Text
	}
	result := db.ScanPage(scanned)
	out := securityScanResult{
		OK:             true,
		ContextID:      contextID,
		SessionID:      sessionID,
		URL:            redactPanelURLSecrets(page.URL),
		Title:          truncateSecuritySnippet(page.Title, 120),
		RiskScore:      result.RiskScore,
		Clean:          result.Clean,
		MatchCount:     len(result.Matches),
		Matches:        sanitizeSecurityMatches(result.Matches, 25),
		ScannedBytes:   len(scanned),
		Threshold:      p.Threshold,
		KillOnRisk:     p.KillOnRisk,
		SignatureCount: db.Count(),
		ScannedAt:      time.Now().UTC(),
		Status:         securityScanStatus(result.Clean, result.RiskScore),
	}
	if p.KillOnRisk && !result.Clean && result.RiskScore >= p.Threshold {
		kill := api.triggerSecurityKillSwitch(fmt.Sprintf("scanner risk %.2f met threshold %.2f", result.RiskScore, p.Threshold))
		out.KillSwitch = &kill
	}
	api.securityScanner().SetLastScan(out)
	return json.Marshal(out)
}

func (api *PanelAPI) securityKillSwitch(params json.RawMessage) (json.RawMessage, error) {
	var p struct {
		Reason string `json:"reason"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	result := api.triggerSecurityKillSwitch(p.Reason)
	return json.Marshal(result)
}

func (api *PanelAPI) readSecurityScanPage(sessionID string) (securityPageSnapshot, error) {
	raw, err := api.Client.Call(sessionID, "Page.getOptimizedDOM", map[string]interface{}{
		"maxDepth": 12,
		"maxNodes": 500,
		"maxChars": 200,
	})
	if err != nil {
		return api.readSecurityScanAXTree(sessionID)
	}
	var domResult struct {
		Snapshot  optimizedDOMSnapshot `json:"snapshot"`
		Result    optimizedDOMSnapshot `json:"result"`
		Truncated bool                 `json:"truncated"`
	}
	if err := json.Unmarshal(raw, &domResult); err != nil {
		return securityPageSnapshot{}, fmt.Errorf("parse scan page result: %w", err)
	}
	snapshot := domResult.Snapshot
	if snapshot.URL == "" && snapshot.Title == "" && len(snapshot.Nodes) == 0 {
		snapshot = domResult.Result
	}
	return securityPageSnapshot{
		URL:   snapshot.URL,
		Title: snapshot.Title,
		Text:  string(snapshot.Nodes),
		HTML:  string(raw),
	}, nil
}

func (api *PanelAPI) readSecurityScanAXTree(sessionID string) (securityPageSnapshot, error) {
	raw, err := api.Client.Call(sessionID, "Accessibility.getFullAXTree", map[string]interface{}{})
	if err != nil {
		return securityPageSnapshot{}, fmt.Errorf("scan page: %w", err)
	}
	return securityPageSnapshot{
		Text: string(raw),
		HTML: string(raw),
	}, nil
}

func (api *PanelAPI) triggerSecurityKillSwitch(reason string) securityKillResult {
	reason = truncateSecuritySnippet(strings.TrimSpace(reason), 240)
	if reason == "" {
		reason = "manual security kill switch"
	}
	result := securityKillResult{
		Activated:   true,
		Reason:      reason,
		TriggeredAt: time.Now().UTC(),
	}
	if api.Orchestrator != nil && api.Orchestrator.Agents != nil {
		result.KilledAgents = api.Orchestrator.Agents.Count()
		api.Orchestrator.Agents.KillAll()
	}
	if api.Kernel != nil && api.Kernel.Running() {
		if err := api.Kernel.Stop(); err != nil {
			result.Error = err.Error()
		} else {
			result.BrowserStopped = true
		}
	}
	api.securityScanner().SetKillSwitch(result)
	return result
}

func (api *PanelAPI) securityScanner() *SecurityScanner {
	if api.Security == nil {
		api.Security = &SecurityScanner{}
	}
	return api.Security
}

func (s *SecurityScanner) Snapshot() SecurityScanner {
	if s == nil {
		return SecurityScanner{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := SecurityScanner{}
	if s.LastScan != nil {
		scan := *s.LastScan
		scan.Matches = append([]securityScanMatch(nil), s.LastScan.Matches...)
		out.LastScan = &scan
	}
	if s.KillSwitch != nil {
		kill := *s.KillSwitch
		out.KillSwitch = &kill
	}
	return out
}

func (s *SecurityScanner) SetLastScan(scan securityScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastScan = &scan
}

func (s *SecurityScanner) SetKillSwitch(kill securityKillResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.KillSwitch = &kill
}

func sanitizeSecurityMatches(matches []security.Match, limit int) []securityScanMatch {
	if len(matches) > limit {
		matches = matches[:limit]
	}
	out := make([]securityScanMatch, len(matches))
	for i, match := range matches {
		out[i] = securityScanMatch{
			Pattern:  match.Pattern,
			Content:  truncateSecuritySnippet(match.Content, 140),
			Severity: match.Severity,
			Position: match.Position,
		}
	}
	return out
}

func truncateSecuritySnippet(value string, limit int) string {
	value = redactPanelURLSecrets(value)
	value = securitySnippetSecretPattern.ReplaceAllString(value, "$1=[redacted]")
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func securityScanStatus(clean bool, risk float64) string {
	if clean {
		return "clean"
	}
	if risk >= 0.7 {
		return "critical"
	}
	return "warning"
}

func (api *PanelAPI) ensureScriptSession(contextID string) (string, string, error) {
	if api.Client == nil {
		return "", "", fmt.Errorf("juggler client not available")
	}
	var err error
	if strings.TrimSpace(contextID) != "" {
		contextID, err = safePanelContextID(contextID)
		if err != nil {
			return "", "", err
		}
	}
	if api.Contexts != nil {
		if contextID == "" {
			if contexts := api.Contexts.List(); len(contexts) > 0 {
				contextID = contexts[0].ID
			}
		}
		if contextID != "" {
			if sessionID := api.Contexts.SessionForContext(contextID); sessionID != "" {
				return contextID, sessionID, nil
			}
		}
	}

	if contextID == "" {
		result, err := api.Client.Call("", "Browser.createBrowserContext", map[string]interface{}{"removeOnDetach": false})
		if err != nil {
			return "", "", err
		}
		var created juggler.CreateBrowserContextResult
		if err := json.Unmarshal(result, &created); err != nil {
			return "", "", fmt.Errorf("parse createBrowserContext result: %w", err)
		}
		contextID = created.BrowserContextID
		if api.Contexts != nil {
			api.Contexts.Created(contextID)
		}
	}

	sessionCh := make(chan string, 4)
	if api.Client != nil {
		unsubscribe := api.Client.SubscribeWithCancel("Browser.attachedToTarget", func(_ string, params json.RawMessage) {
			var ev juggler.AttachedToTarget
			if err := json.Unmarshal(params, &ev); err == nil && ev.TargetInfo.BrowserContextID == contextID && ev.SessionID != "" {
				select {
				case sessionCh <- ev.SessionID:
				default:
				}
			}
		})
		defer unsubscribe()
	}

	if _, err := api.Client.Call("", "Browser.newPage", map[string]interface{}{"browserContextId": contextID}); err != nil {
		return "", "", err
	}

	sessionID, err := api.waitForContextSession(contextID, sessionCh, 10*time.Second)
	if err != nil {
		return "", "", err
	}
	return contextID, sessionID, nil
}

func (api *PanelAPI) waitForContextSession(contextID string, sessionCh <-chan string, timeout time.Duration) (string, error) {
	if api.Contexts != nil {
		if sessionID := api.Contexts.SessionForContext(contextID); sessionID != "" {
			return sessionID, nil
		}
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if api.Contexts != nil {
			if sessionID := api.Contexts.SessionForContext(contextID); sessionID != "" {
				return sessionID, nil
			}
		}
		select {
		case sessionID := <-sessionCh:
			return sessionID, nil
		case <-ticker.C:
		case <-deadline.C:
			return "", fmt.Errorf("timed out waiting for page session")
		}
	}
}

func ternaryStatus(cond bool, yes string, no string) string {
	if cond {
		return yes
	}
	return no
}

func ternaryText(cond bool, yes string, no string) string {
	if cond {
		return yes
	}
	return no
}

func joinStrings(values []string, sep string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for i := 1; i < len(values); i++ {
		out += sep + values[i]
	}
	return out
}
