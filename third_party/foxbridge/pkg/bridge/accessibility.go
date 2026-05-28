package bridge

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/VulpineOS/foxbridge/pkg/cdp"
)

func (b *Bridge) handleAccessibility(conn *cdp.Connection, msg *cdp.Message) (json.RawMessage, *cdp.Error) {
	switch msg.Method {
	case "Accessibility.enable", "Accessibility.disable":
		return json.RawMessage(`{}`), nil

	case "Accessibility.getFullAXTree":
		result, err := b.callJuggler(msg.SessionID, "Accessibility.getFullAXTree", nil)
		if err != nil {
			return nil, &cdp.Error{Code: -32000, Message: err.Error()}
		}
		b.attachAccessibilityNodeObjects(msg.SessionID, result)
		return result, nil

	default:
		return nil, &cdp.Error{Code: -32601, Message: fmt.Sprintf("method not found: %s", msg.Method)}
	}
}

func (b *Bridge) attachAccessibilityNodeObjects(cdpSessionID string, result json.RawMessage) {
	var payload struct {
		Nodes []map[string]interface{} `json:"nodes"`
	}
	if err := json.Unmarshal(result, &payload); err != nil || len(payload.Nodes) == 0 {
		return
	}

	seen := make(map[string]int)
	for _, node := range payload.Nodes {
		backendID, ok := axBackendDOMNodeID(node["backendDOMNodeId"])
		if !ok {
			continue
		}
		role := axValueString(node["role"])
		name := axValueString(node["name"])
		if !isAXInteractiveRole(role) || strings.TrimSpace(name) == "" {
			continue
		}
		key := role + "\x00" + name
		ordinal := seen[key]
		seen[key] = ordinal + 1
		objectID := b.resolveAXNodeObjectID(cdpSessionID, role, name, ordinal)
		if objectID == "" {
			continue
		}
		b.setNodeObject(cdpSessionID, backendID, objectID)
	}
}

func (b *Bridge) resolveAXNodeObjectID(cdpSessionID, role, name string, ordinal int) string {
	execCtx := b.latestContextForSession(cdpSessionID)
	expr := fmt.Sprintf(`(() => {
  const wantedRole = %q;
  const wantedName = %q;
  const wantedOrdinal = %d;
  const candidates = Array.from(document.querySelectorAll('a,button,input,textarea,select,[role],[tabindex]'));
  function roleOf(el) {
    const explicit = el.getAttribute('role');
    if (explicit) return explicit.toLowerCase();
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (tag === 'a' && el.href) return 'link';
    if (tag === 'button') return 'button';
    if (tag === 'select') return 'combobox';
    if (tag === 'textarea') return 'textbox';
    if (tag === 'input') {
      if (type === 'button' || type === 'submit' || type === 'reset') return 'button';
      if (type === 'checkbox') return 'checkbox';
      if (type === 'radio') return 'radio';
      return 'textbox';
    }
    return explicit || '';
  }
  function nameOf(el) {
    return (el.getAttribute('aria-label') || el.getAttribute('alt') || el.getAttribute('title') ||
      ((el.tagName || '').toLowerCase() === 'input' ? el.value : '') || el.innerText || el.textContent || '').trim();
  }
  let seen = 0;
  for (const el of candidates) {
    if (roleOf(el) !== wantedRole) continue;
    if (nameOf(el) !== wantedName) continue;
    if (seen === wantedOrdinal) return el;
    seen++;
  }
  return null;
})()`, strings.ToLower(role), name, ordinal)

	params := map[string]interface{}{
		"expression":    expr,
		"returnByValue": false,
	}
	if execCtx != "" {
		params["executionContextId"] = execCtx
	}
	result, err := b.callJuggler(cdpSessionID, "Runtime.evaluate", params)
	if err != nil {
		return ""
	}
	var evalResult struct {
		Result struct {
			ObjectID string `json:"objectId"`
			Subtype  string `json:"subtype"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result, &evalResult); err == nil {
		if evalResult.Result.ObjectID != "" && evalResult.Result.Subtype != "null" {
			return evalResult.Result.ObjectID
		}
	}

	var directResult struct {
		ObjectID string `json:"objectId"`
		Subtype  string `json:"subtype"`
	}
	if err := json.Unmarshal(result, &directResult); err != nil {
		return ""
	}
	if directResult.ObjectID == "" || directResult.Subtype == "null" {
		return ""
	}
	return directResult.ObjectID
}

func axBackendDOMNodeID(value interface{}) (int, bool) {
	switch id := value.(type) {
	case int:
		return id, id > 0
	case int64:
		return int(id), id > 0
	case uint64:
		return int(id), id > 0
	case float64:
		asInt := int(id)
		return asInt, id > 0 && float64(asInt) == id
	}
	return 0, false
}

func axValueString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]interface{}:
		if raw, ok := v["value"]; ok {
			if s, ok := raw.(string); ok {
				return s
			}
		}
	}
	return ""
}

func isAXInteractiveRole(role string) bool {
	switch strings.ToLower(role) {
	case "button", "link", "checkbox", "radio", "textbox", "combobox", "menuitem", "tab", "switch", "slider", "spinbutton", "searchbox":
		return true
	default:
		return false
	}
}
