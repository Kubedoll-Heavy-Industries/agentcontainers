package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

// SaveCapabilities updates the agent.capabilities section of an agentcontainer.json
// file, preserving all comments and formatting in the rest of the file.
// If the "agent" or "capabilities" keys do not exist, they are created.
func SaveCapabilities(path string, caps *Capabilities) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("save: reading file: %w", err)
	}
	perm := fi.Mode().Perm()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("save: reading file: %w", err)
	}

	updated, err := patchCapabilities(data, caps)
	if err != nil {
		return fmt.Errorf("save: %w", err)
	}

	if err := os.WriteFile(path, updated, perm); err != nil {
		return fmt.Errorf("save: writing file: %w", err)
	}

	return nil
}

// patchCapabilities applies the capabilities change to the raw JSONC bytes,
// returning the updated bytes with comments preserved. It is separated from
// SaveCapabilities so that it can be tested without touching the filesystem.
func patchCapabilities(data []byte, caps *Capabilities) ([]byte, error) {
	root, err := hujson.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing JSONC: %w", err)
	}

	capsJSON, err := json.Marshal(caps)
	if err != nil {
		return nil, fmt.Errorf("marshaling capabilities: %w", err)
	}

	patch, err := buildCapabilitiesPatch(&root, capsJSON)
	if err != nil {
		return nil, err
	}

	if err := root.Patch(patch); err != nil {
		return nil, fmt.Errorf("applying patch: %w", err)
	}

	root.Format()
	return root.Pack(), nil
}

// buildCapabilitiesPatch constructs the minimal RFC 6902 JSON Patch needed
// to set /agent/capabilities to the supplied value.
func buildCapabilitiesPatch(root *hujson.Value, capsJSON []byte) ([]byte, error) {
	type patchOp struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	}

	var ops []patchOp

	agentVal := root.Find("/agent")
	if agentVal == nil {
		agentObj := map[string]json.RawMessage{"capabilities": capsJSON}
		agentJSON, err := json.Marshal(agentObj)
		if err != nil {
			return nil, fmt.Errorf("marshaling agent object: %w", err)
		}
		ops = append(ops, patchOp{Op: "add", Path: "/agent", Value: agentJSON})
	} else {
		capsVal := root.Find("/agent/capabilities")
		if capsVal == nil {
			ops = append(ops, patchOp{Op: "add", Path: "/agent/capabilities", Value: capsJSON})
		} else {
			ops = append(ops, patchOp{Op: "replace", Path: "/agent/capabilities", Value: capsJSON})
		}
	}

	patchJSON, err := json.Marshal(ops)
	if err != nil {
		return nil, fmt.Errorf("marshaling patch: %w", err)
	}
	return patchJSON, nil
}
