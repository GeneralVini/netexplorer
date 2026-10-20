// Package tools locates optional executables without running or installing them.
package tools

import "os/exec"

// Info describes an executable lookup result, not a tested runtime capability.
type Info struct {
	// Name is the executable name requested by the caller.
	Name string `json:"name"`
	// Path is the executable path, or empty when lookup fails.
	Path string `json:"path,omitempty"`
	// Available reports whether exec.LookPath succeeded.
	Available bool `json:"available"`
}

// Discover locates executable names through PATH without running them.
// The returned entries preserve the order of names, including unavailable tools.
func Discover(names ...string) []Info {
	result := make([]Info, 0, len(names))
	for _, name := range names {
		path, err := exec.LookPath(name)
		result = append(result, Info{Name: name, Path: path, Available: err == nil})
	}
	return result
}
