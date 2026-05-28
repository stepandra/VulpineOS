package foxbridge

import (
	"encoding/json"
	"testing"
)

func TestNormalizeAccessibilityAlreadyNormalizedNodesStayValid(t *testing.T) {
	raw := json.RawMessage(`{
		"nodes": [{
			"nodeId": "1",
			"role": {"type":"role","value":"button"},
			"name": {"type":"string","value":"Submit"},
			"ignored": false,
			"backendDOMNodeId": 42,
			"properties": [{"name":"focusable","value":{"type":"boolean","value":true}}]
		}],
		"filtered": true
	}`)

	out := normalizeAXResultForTest(t, raw)
	nodes := requireNodes(t, out, 1)
	node := nodes[0]
	if node["nodeId"] != "1" {
		t.Fatalf("nodeId = %#v, want string 1", node["nodeId"])
	}
	if node["ignored"] != false {
		t.Fatalf("ignored = %#v, want false", node["ignored"])
	}
	if node["backendDOMNodeId"] != float64(42) {
		t.Fatalf("backendDOMNodeId = %#v, want 42", node["backendDOMNodeId"])
	}
	if out["filtered"] != true {
		t.Fatalf("filtered = %#v, want true", out["filtered"])
	}
}

func TestNormalizeAccessibilityTreeInputConvertsToNodes(t *testing.T) {
	raw := json.RawMessage(`{
		"tree": {
			"role": "document",
			"name": "Example",
			"children": [
				{"nodeId":"link-1","role":"link","name":"More information","focused":true},
				{"id": 9,"role":"button","name":"OK","value":7,"description":"Confirm"}
			]
		},
		"filtered": true
	}`)

	out := normalizeAXResultForTest(t, raw)
	nodes := requireNodes(t, out, 3)
	root := nodes[0]
	if _, hasTree := out["tree"]; hasTree {
		t.Fatal("normalized payload should not expose top-level tree")
	}
	if root["nodeId"] != "1" {
		t.Fatalf("root nodeId = %#v, want generated string 1", root["nodeId"])
	}
	childIDs, ok := root["childIds"].([]any)
	if !ok || len(childIDs) != 2 || childIDs[0] != "link-1" || childIDs[1] != float64(9) {
		t.Fatalf("root childIds = %#v, want [link-1 9]", root["childIds"])
	}
	if valueOfAXValue(t, root["role"]) != "document" {
		t.Fatalf("root role = %#v", root["role"])
	}
	if valueOfAXValue(t, nodes[1]["name"]) != "More information" {
		t.Fatalf("link name = %#v", nodes[1]["name"])
	}
	props, ok := nodes[1]["properties"].([]any)
	if !ok || len(props) == 0 {
		t.Fatalf("expected raw state properties, got %#v", nodes[1]["properties"])
	}
	if valueOfAXValue(t, nodes[2]["value"]) != float64(7) {
		t.Fatalf("numeric value not normalized: %#v", nodes[2]["value"])
	}
	if nodes[1]["backendDOMNodeId"] == nil || nodes[2]["backendDOMNodeId"] == nil {
		t.Fatalf("expected synthesized backendDOMNodeId values: %#v %#v", nodes[1], nodes[2])
	}
}

func TestNormalizeAccessibilityRawRootAndMissingOptionalFields(t *testing.T) {
	raw := json.RawMessage(`{"role":"document","name":"Only root"}`)

	out := normalizeAXResultForTest(t, raw)
	nodes := requireNodes(t, out, 1)
	if valueOfAXValue(t, nodes[0]["name"]) != "Only root" {
		t.Fatalf("name = %#v", nodes[0]["name"])
	}
	if _, ok := nodes[0]["childIds"]; !ok {
		t.Fatal("missing childIds should be normalized to an empty list")
	}
}

func TestNormalizeAccessibilityPreservesNumericAndStringNodeIDs(t *testing.T) {
	raw := json.RawMessage(`{"nodes":[{"nodeId":2,"role":"text","name":"Number"},{"nodeId":"3","role":"text","name":"String"}]}`)

	out := normalizeAXResultForTest(t, raw)
	nodes := requireNodes(t, out, 2)
	if nodes[0]["nodeId"] != float64(2) {
		t.Fatalf("numeric nodeId = %#v, want 2", nodes[0]["nodeId"])
	}
	if nodes[1]["nodeId"] != "3" {
		t.Fatalf("string nodeId = %#v, want 3", nodes[1]["nodeId"])
	}
}

func normalizeAXResultForTest(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	normalized, err := normalizeAccessibilityResult(accessibilityGetFullAXTree, raw)
	if err != nil {
		t.Fatalf("normalizeAccessibilityResult: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(normalized, &out); err != nil {
		t.Fatalf("unmarshal normalized result: %v", err)
	}
	return out
}

func requireNodes(t *testing.T, out map[string]any, want int) []map[string]any {
	t.Helper()
	rawNodes, ok := out["nodes"].([]any)
	if !ok {
		t.Fatalf("nodes missing or wrong type: %#v", out["nodes"])
	}
	if len(rawNodes) != want {
		t.Fatalf("nodes length = %d, want %d: %#v", len(rawNodes), want, rawNodes)
	}
	nodes := make([]map[string]any, 0, len(rawNodes))
	for _, rawNode := range rawNodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			t.Fatalf("node has wrong type: %#v", rawNode)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func valueOfAXValue(t *testing.T, raw any) any {
	t.Helper()
	value, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("AXValue has wrong type: %#v", raw)
	}
	return value["value"]
}
