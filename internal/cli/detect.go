package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// devcontainerSearchPaths lists the standard locations where a devcontainer.json
// may be found, in priority order.
var devcontainerSearchPaths = []string{
	".devcontainer/devcontainer.json",
	"devcontainer.json",
}

// composeSearchNames lists file names treated as Compose files when referenced
// from a devcontainer.json.
var composeSearchNames = []string{
	"docker-compose.yml",
	"docker-compose.yaml",
	"compose.yml",
	"compose.yaml",
}

// DetectedDevcontainer holds the information extracted from a found
// devcontainer.json file.
type DetectedDevcontainer struct {
	// Path is the absolute path to the devcontainer.json that was found.
	Path string

	// Name is the "name" field from the devcontainer config.
	Name string

	// Image is the "image" field, if specified.
	Image string

	// Build holds the "build" section, if specified.
	Build *DetectedBuild

	// DockerComposeFile holds the "dockerComposeFile" reference(s), if any.
	DockerComposeFile []string

	// ComposeFilesFound lists absolute paths to compose files that were
	// actually found on disk.
	ComposeFilesFound []string
}

// DetectedBuild captures the build-related fields from a devcontainer.json.
type DetectedBuild struct {
	Dockerfile string            `json:"dockerfile,omitempty"`
	Context    string            `json:"context,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

// rawDevcontainer is used for JSON unmarshalling of the subset of
// devcontainer.json fields we care about.
type rawDevcontainer struct {
	Name              string          `json:"name,omitempty"`
	Image             string          `json:"image,omitempty"`
	Build             json.RawMessage `json:"build,omitempty"`
	DockerComposeFile json.RawMessage `json:"dockerComposeFile,omitempty"`
}

// findDevcontainer searches for a devcontainer.json in the given workspace
// directory. It returns nil if no devcontainer.json is found.
func findDevcontainer(dir string) (*DetectedDevcontainer, error) {
	for _, rel := range devcontainerSearchPaths {
		abs := filepath.Join(dir, rel)
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		return parseDevcontainer(abs, dir)
	}
	return nil, nil
}

// parseDevcontainer reads and extracts information from a devcontainer.json file.
func parseDevcontainer(path, workspaceDir string) (*DetectedDevcontainer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Strip JSONC comments so standard encoding/json can parse it.
	data = stripJSONComments(data)

	var raw rawDevcontainer
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	det := &DetectedDevcontainer{
		Path:  path,
		Name:  raw.Name,
		Image: raw.Image,
	}

	// Parse build section.
	if len(raw.Build) > 0 {
		var b DetectedBuild
		if err := json.Unmarshal(raw.Build, &b); err == nil && (b.Dockerfile != "" || b.Context != "") {
			det.Build = &b
		}
	}

	// Parse dockerComposeFile -- can be a string or array of strings.
	if len(raw.DockerComposeFile) > 0 {
		det.DockerComposeFile = parseStringOrArray(raw.DockerComposeFile)
	}

	// Detect compose files on disk.
	det.ComposeFilesFound = detectComposeFiles(workspaceDir)

	return det, nil
}

// parseStringOrArray handles the devcontainer.json convention where
// dockerComposeFile can be either "file.yml" or ["file1.yml","file2.yml"].
func parseStringOrArray(raw json.RawMessage) []string {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		return multi
	}
	return nil
}

// detectComposeFiles looks for common docker-compose / compose file names
// in the workspace root and returns their absolute paths.
func detectComposeFiles(dir string) []string {
	var found []string
	for _, name := range composeSearchNames {
		abs := filepath.Join(dir, name)
		if _, err := os.Stat(abs); err == nil {
			found = append(found, abs)
		}
	}
	return found
}

// stripJSONComments performs a simple removal of single-line (//) and
// multi-line (/* */) comments from JSONC content so it can be fed to
// encoding/json. It respects quoted strings.
func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		// Inside a JSON string -- copy verbatim until closing quote.
		if data[i] == '"' {
			out = append(out, data[i])
			i++
			for i < len(data) {
				out = append(out, data[i])
				if data[i] == '\\' {
					i++
					if i < len(data) {
						out = append(out, data[i])
					}
				} else if data[i] == '"' {
					i++
					break
				}
				i++
			}
			continue
		}

		// Single-line comment.
		if i+1 < len(data) && data[i] == '/' && data[i+1] == '/' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}

		// Multi-line comment.
		if i+1 < len(data) && data[i] == '/' && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) {
				if data[i] == '*' && data[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		out = append(out, data[i])
		i++
	}
	return out
}
