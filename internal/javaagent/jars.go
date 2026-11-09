package javaagent

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// The agent's jars as built from java/ (make jars), embedded so that
// --java works for a snoopy built with go install, which has nothing next
// to it. CI checks they're what java/build.sh builds from the sources.
var (
	//go:embed jars/snoopy-agent.jar
	embeddedAgent []byte
	//go:embed jars/snoopy-hooks.jar
	embeddedHooks []byte
)

// Jars are the agent's two files' contents.
type Jars struct {
	Agent, Hooks []byte
}

// Embedded returns the jars built into snoopy.
func Embedded() Jars {
	return Jars{embeddedAgent, embeddedHooks}
}

// LoadJars reads the jars from a directory.
func LoadJars(dir string) (Jars, error) {
	var j Jars
	for name, to := range map[string]*[]byte{AgentJar: &j.Agent, HooksJar: &j.Hooks} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return Jars{}, fmt.Errorf("the Java agent: %w", err)
		}
		*to = data
	}
	return j, nil
}
