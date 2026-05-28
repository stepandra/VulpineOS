package juggler

import (
	"os"
	"strings"
	"testing"
)

func readRuntimeSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../additions/juggler/content/Runtime.js")
	if err != nil {
		t.Fatalf("read Runtime.js: %v", err)
	}
	return string(data)
}

func TestRuntimeEvaluateWaitsForExecutionContextTransition(t *testing.T) {
	source := readRuntimeSource(t)

	required := []string{
		"const RUNTIME_CONTEXT_WAIT_TIMEOUT_MS = 750;",
		"const RUNTIME_CONTEXT_TIMEOUT_CODE = 'ERR_RUNTIME_CONTEXT_TIMEOUT';",
		"const executionContext = await this._resolveExecutionContext(executionContextId);",
		"async _waitForExecutionContext(requestedExecutionContextId)",
		"this.events.onExecutionContextCreated(context =>",
		"setTimeout(() =>",
		"error.code = RUNTIME_CONTEXT_TIMEOUT_CODE;",
	}
	for _, needle := range required {
		if !strings.Contains(source, needle) {
			t.Fatalf("Runtime.js missing %q", needle)
		}
	}

	waitIndex := strings.Index(source, "async _waitForExecutionContext(requestedExecutionContextId)")
	if waitIndex == -1 {
		t.Fatal("Runtime.js missing _waitForExecutionContext")
	}
	waitBody := source[waitIndex:]
	timerIndex := strings.Index(waitBody, "setTimeout(() =>")
	listenerIndex := strings.Index(waitBody, "this.events.onExecutionContextCreated(context =>")
	if timerIndex == -1 || listenerIndex == -1 {
		t.Fatal("Runtime.js does not register both timeout and executionContextCreated waiter")
	}
}

func TestRuntimeEvaluateAndCallFunctionUseSharedContextResolver(t *testing.T) {
	source := readRuntimeSource(t)

	evaluateIndex := strings.Index(source, "async evaluate({executionContextId, expression, returnByValue})")
	callFunctionIndex := strings.Index(source, "async callFunction({executionContextId, functionDeclaration, args, returnByValue})")
	resolverIndex := strings.Index(source, "async _resolveExecutionContext(executionContextId)")
	if evaluateIndex == -1 || callFunctionIndex == -1 || resolverIndex == -1 {
		t.Fatal("Runtime.js missing evaluate/callFunction/shared resolver structure")
	}

	evaluateBody := source[evaluateIndex:callFunctionIndex]
	if !strings.Contains(evaluateBody, "await this._resolveExecutionContext(executionContextId)") {
		t.Fatal("Runtime.evaluate does not use the bounded context resolver")
	}
	callFunctionBody := source[callFunctionIndex:resolverIndex]
	if !strings.Contains(callFunctionBody, "await this._resolveExecutionContext(executionContextId)") {
		t.Fatal("Runtime.callFunction does not use the bounded context resolver")
	}
}

func TestRuntimeRemoteObjectsIncludeCDPType(t *testing.T) {
	source := readRuntimeSource(t)

	required := []string{
		"_primitiveToRemoteObject(value)",
		"return {type: typeof value, value};",
		"return {type: 'object', subtype: 'null', value: null}",
		"return {type: 'undefined'}",
		"return {type: 'number', unserializableValue: 'NaN'}",
		"return {type: 'number', unserializableValue: '-0'}",
		"return this._primitiveToRemoteObject(this._serialize(obj));",
	}
	for _, needle := range required {
		if !strings.Contains(source, needle) {
			t.Fatalf("Runtime.js missing RemoteObject shape fragment %q", needle)
		}
	}
}

func TestRuntimeContextTimeoutErrorIsMachineReadable(t *testing.T) {
	source := readRuntimeSource(t)
	if !strings.Contains(source, "ERR_RUNTIME_CONTEXT_TIMEOUT") {
		t.Fatal("Runtime.js missing stable timeout code")
	}
	if !strings.Contains(source, "error.code = RUNTIME_CONTEXT_TIMEOUT_CODE;") {
		t.Fatal("Runtime.js does not attach timeout code to protocol error")
	}

	data, err := os.ReadFile("../../additions/juggler/protocol/Dispatcher.js")
	if err != nil {
		t.Fatalf("read Dispatcher.js: %v", err)
	}
	if !strings.Contains(string(data), "code: e.code") {
		t.Fatal("Dispatcher.js does not forward machine-readable error code")
	}
}

func TestSelectorInputHelperStillCombinesResolveAndNativeSet(t *testing.T) {
	data, err := os.ReadFile("extension_methods.go")
	if err != nil {
		t.Fatalf("read extension_methods.go: %v", err)
	}
	source := string(data)

	required := []string{
		"func (c *Client) SecureSetInputValueBySelector",
		"document.querySelector(%s)",
		"\"returnByValue\": false",
		"c.SecureSetInputValue(ctx, sessionID, frameID, resp.Result.ObjectID, value)",
	}
	for _, needle := range required {
		if !strings.Contains(source, needle) {
			t.Fatalf("selector helper missing %q", needle)
		}
	}
}
