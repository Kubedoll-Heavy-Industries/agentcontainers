package skillbom

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SkillMetadata holds parsed metadata from a skill directory.
type SkillMetadata struct {
	Name         string
	Version      string
	Description  string
	Capabilities []string
}

// ParseSkillDir extracts skill metadata from a directory.
// It reads SKILL.md frontmatter first; falls back to capabilities.json.
func ParseSkillDir(dir string) (*SkillMetadata, error) {
	skillPath := filepath.Join(dir, "SKILL.md")
	data, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("reading SKILL.md: %w", err)
	}

	meta, err := parseFrontmatter(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing SKILL.md frontmatter: %w", err)
	}

	// If no capabilities from frontmatter, try capabilities.json sidecar.
	if len(meta.Capabilities) == 0 {
		caps, err := parseCapabilitiesJSON(filepath.Join(dir, "capabilities.json"))
		if err == nil {
			meta.Capabilities = caps
		}
		// Not an error if missing; skills may declare no capabilities.
	}

	sort.Strings(meta.Capabilities)
	return meta, nil
}

// parseFrontmatter extracts YAML-like frontmatter from SKILL.md content.
// Frontmatter is delimited by --- on the first line and a subsequent ---.
// We parse simple key: value and list items (- value) without a full YAML library.
func parseFrontmatter(content string) (*SkillMetadata, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "---" {
		return &SkillMetadata{}, nil // No frontmatter
	}

	var fmLines []string
	closed := false
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			closed = true
			break
		}
		fmLines = append(fmLines, line)
	}
	if !closed {
		return &SkillMetadata{}, nil // Unclosed frontmatter treated as none
	}

	meta := &SkillMetadata{}
	var currentList *[]string

	for _, line := range fmLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// List item: "  - value"
		if strings.HasPrefix(trimmed, "- ") && currentList != nil {
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			*currentList = append(*currentList, val)
			continue
		}

		// Key: value pair
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			currentList = nil
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "name":
			meta.Name = val
			currentList = nil
		case "version":
			meta.Version = val
			currentList = nil
		case "description":
			meta.Description = val
			currentList = nil
		case "requires":
			if val != "" {
				// Inline list not supported; value after colon ignored
				// if there are subsequent list items.
				meta.Capabilities = nil
			}
			currentList = &meta.Capabilities
		default:
			currentList = nil
		}
	}

	return meta, nil
}

// parseCapabilitiesJSON reads a capabilities.json sidecar file.
func parseCapabilitiesJSON(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var doc struct {
		Requires []string `json:"requires"`
	}
	if err := json.NewDecoder(bufio.NewReader(f)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing capabilities.json: %w", err)
	}
	return doc.Requires, nil
}
