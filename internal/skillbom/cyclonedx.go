package skillbom

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CycloneDX 1.7 types — only the subset needed for SkillBOM generation.

// CDXDocument is a CycloneDX 1.7 BOM document.
type CDXDocument struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     CDXMetadata     `json:"metadata"`
	Components   []CDXComponent  `json:"components"`
	Dependencies []CDXDependency `json:"dependencies,omitempty"`
	Properties   []CDXProperty   `json:"properties,omitempty"`
}

// CDXMetadata is the BOM metadata block.
type CDXMetadata struct {
	Timestamp string        `json:"timestamp"`
	Component *CDXComponent `json:"component,omitempty"`
	Tools     *CDXTools     `json:"tools,omitempty"`
}

// CDXTools lists tools used to generate the BOM.
type CDXTools struct {
	Components []CDXComponent `json:"components,omitempty"`
}

// CDXComponent is a CycloneDX component entry.
type CDXComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Hashes     []CDXHash     `json:"hashes,omitempty"`
	Properties []CDXProperty `json:"properties,omitempty"`
}

// CDXHash is a component hash entry.
type CDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// CDXProperty is a name/value property.
type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CDXDependency is a dependency graph edge.
type CDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// buildCycloneDX constructs a CycloneDX 1.7 document from skill metadata
// and file inventory.
func buildCycloneDX(meta *SkillMetadata, files []fileEntry, contentHash string, acVersion string) ([]byte, error) {
	doc := CDXDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: CDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: &CDXComponent{
				Type:    "application",
				BOMRef:  meta.Name,
				Name:    meta.Name,
				Version: meta.Version,
				Properties: []CDXProperty{
					{Name: "cdx:device:type", Value: "agent-skill"},
				},
			},
		},
	}

	if acVersion != "" {
		doc.Metadata.Tools = &CDXTools{
			Components: []CDXComponent{
				{Type: "application", Name: "ac", Version: acVersion},
			},
		}
	}

	// Build components from file inventory.
	var componentRefs []string
	for _, f := range files {
		comp := CDXComponent{
			Type:   "file",
			BOMRef: f.RelPath,
			Name:   f.RelPath,
			Hashes: []CDXHash{
				{Alg: "SHA-256", Content: f.SHA256},
			},
		}

		// Add semantic content hash property on SKILL.md.
		if f.RelPath == "SKILL.md" {
			comp.Properties = append(comp.Properties, CDXProperty{
				Name:  "agentcontainers:semantic-embedding-hash",
				Value: contentHash,
			})
			comp.Properties = append(comp.Properties, CDXProperty{
				Name:  "agentcontainers:semantic-embedding-model",
				Value: "content-hash-v1",
			})
			comp.Properties = append(comp.Properties, CDXProperty{
				Name:  "agentcontainers:semantic-embedding-version",
				Value: "m1",
			})
		}

		// Mark executable files.
		if f.Executable {
			comp.Properties = append(comp.Properties, CDXProperty{
				Name:  "agentcontainers:executable",
				Value: "true",
			})
		}

		doc.Components = append(doc.Components, comp)
		componentRefs = append(componentRefs, f.RelPath)
	}

	// Top-level dependency: skill depends on all components.
	doc.Dependencies = []CDXDependency{
		{Ref: meta.Name, DependsOn: componentRefs},
	}

	// Top-level properties: required capabilities and drift threshold.
	if len(meta.Capabilities) > 0 {
		capsJSON, err := json.Marshal(meta.Capabilities)
		if err != nil {
			return nil, fmt.Errorf("marshaling capabilities: %w", err)
		}
		doc.Properties = append(doc.Properties, CDXProperty{
			Name:  "agentcontainers:required-capabilities",
			Value: string(capsJSON),
		})
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling CycloneDX document: %w", err)
	}

	return data, nil
}
