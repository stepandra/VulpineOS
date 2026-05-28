package foxbridge

import (
	"encoding/json"
	"fmt"
	"strconv"
)

const accessibilityGetFullAXTree = "Accessibility.getFullAXTree"

var rawAXStateProperties = map[string]struct{}{
	"selected":        {},
	"focused":         {},
	"pressed":         {},
	"focusable":       {},
	"required":        {},
	"invalid":         {},
	"modal":           {},
	"editable":        {},
	"busy":            {},
	"multiline":       {},
	"readonly":        {},
	"checked":         {},
	"expanded":        {},
	"disabled":        {},
	"multiselectable": {},
	"haspopup":        {},
	"roledescription": {},
	"valuetext":       {},
	"orientation":     {},
	"autocomplete":    {},
	"keyshortcuts":    {},
	"level":           {},
}

func normalizeAccessibilityResult(method string, raw json.RawMessage) (json.RawMessage, error) {
	if method != accessibilityGetFullAXTree || len(raw) == 0 {
		return raw, nil
	}

	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parse %s result: %w", method, err)
	}

	normalized, err := normalizeAXPayload(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func normalizeAXPayload(payload any) (map[string]any, error) {
	obj, ok := payload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s result must be an object", accessibilityGetFullAXTree)
	}

	if nodes, ok := obj["nodes"].([]any); ok {
		result := make(map[string]any, len(obj))
		for key, value := range obj {
			result[key] = value
		}
		normalizedNodes := normalizeAXNodes(nodes)
		ensureBackendDOMNodeIDs(normalizedNodes)
		result["nodes"] = normalizedNodes
		return result, nil
	}

	result := map[string]any{}
	root := obj
	if tree, ok := obj["tree"].(map[string]any); ok {
		root = tree
		for key, value := range obj {
			if key == "tree" {
				continue
			}
			result[key] = value
		}
	}

	nextID := 1
	nodes := flattenAXTreeForCDP(root, &nextID)
	ensureBackendDOMNodeIDs(nodes)
	result["nodes"] = nodes
	return result, nil
}

func normalizeAXNodes(nodes []any) []any {
	normalized := make([]any, 0, len(nodes))
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			normalized = append(normalized, rawNode)
			continue
		}
		normalized = append(normalized, normalizeAXNode(node, nil))
	}
	return normalized
}

func flattenAXTreeForCDP(root map[string]any, nextID *int) []any {
	nodes := []any{}
	var walk func(map[string]any) any
	walk = func(node map[string]any) any {
		if node == nil {
			return nil
		}

		nodeID := axNodeID(node)
		if nodeID == nil {
			nodeID = strconv.Itoa(*nextID)
			*nextID = *nextID + 1
		}

		childIDs := []any{}
		children, _ := node["children"].([]any)
		childNodes := make([]map[string]any, 0, len(children))
		for _, rawChild := range children {
			child, ok := rawChild.(map[string]any)
			if !ok {
				continue
			}
			childID := axNodeID(child)
			if childID == nil {
				childID = strconv.Itoa(*nextID)
				*nextID = *nextID + 1
				child["nodeId"] = childID
			}
			childIDs = append(childIDs, childID)
			childNodes = append(childNodes, child)
		}

		cdpNode := normalizeAXNode(node, childIDs)
		cdpNode["nodeId"] = nodeID
		nodes = append(nodes, cdpNode)

		for _, child := range childNodes {
			walk(child)
		}
		return nodeID
	}
	walk(root)
	return nodes
}

func normalizeAXNode(node map[string]any, childIDs []any) map[string]any {
	out := make(map[string]any, len(node)+2)
	for key, value := range node {
		if key == "children" {
			continue
		}
		out[key] = value
	}

	if nodeID := axNodeID(node); nodeID != nil {
		out["nodeId"] = nodeID
	}
	for _, field := range []string{"role", "name", "value", "description"} {
		if value, ok := node[field]; ok {
			out[field] = normalizeAXValue(field, value)
		}
	}
	if properties, ok := node["properties"].([]any); ok {
		out["properties"] = normalizeAXProperties(properties)
	} else {
		props := propertiesFromRawAXState(node)
		if len(props) > 0 {
			out["properties"] = props
		}
	}
	if ignoredReasons, ok := node["ignoredReasons"].([]any); ok {
		out["ignoredReasons"] = normalizeAXProperties(ignoredReasons)
	}
	if childIDs != nil {
		out["childIds"] = childIDs
	} else if existingChildIDs, ok := node["childIds"]; ok {
		out["childIds"] = existingChildIDs
	}
	return out
}

func ensureBackendDOMNodeIDs(nodes []any) {
	nextBackendID := 1
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := node["backendDOMNodeId"]; ok {
			continue
		}
		if numericID, ok := numericAXNodeID(node["nodeId"]); ok {
			node["backendDOMNodeId"] = numericID
			if numericID >= nextBackendID {
				nextBackendID = numericID + 1
			}
			continue
		}
		node["backendDOMNodeId"] = nextBackendID
		nextBackendID++
	}
}

func numericAXNodeID(value any) (int, bool) {
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

func normalizeAXProperties(properties []any) []any {
	out := make([]any, 0, len(properties))
	for _, rawProperty := range properties {
		property, ok := rawProperty.(map[string]any)
		if !ok {
			out = append(out, rawProperty)
			continue
		}
		copyProperty := make(map[string]any, len(property))
		for key, value := range property {
			copyProperty[key] = value
		}
		if value, ok := property["value"]; ok {
			copyProperty["value"] = normalizeAXValue("value", value)
		}
		out = append(out, copyProperty)
	}
	return out
}

func propertiesFromRawAXState(node map[string]any) []any {
	props := []any{}
	for key, value := range node {
		if _, ok := rawAXStateProperties[key]; !ok {
			continue
		}
		props = append(props, map[string]any{
			"name":  key,
			"value": normalizeAXValue("value", value),
		})
	}
	return props
}

func normalizeAXValue(field string, value any) any {
	if valueMap, ok := value.(map[string]any); ok {
		if _, hasType := valueMap["type"]; hasType {
			if _, hasValue := valueMap["value"]; hasValue {
				return value
			}
		}
	}

	valueType := "string"
	if field == "role" {
		valueType = "role"
	} else {
		switch value.(type) {
		case bool:
			valueType = "boolean"
		case float64, float32, int, int64, uint64:
			valueType = "number"
		}
	}
	return map[string]any{
		"type":  valueType,
		"value": value,
	}
}

func axNodeID(node map[string]any) any {
	if node == nil {
		return nil
	}
	if id, ok := node["nodeId"]; ok && id != nil && id != "" {
		return id
	}
	if id, ok := node["id"]; ok && id != nil && id != "" {
		return id
	}
	return nil
}
