package main

import (
	"github.com/tinyworks/tinymount/cmd"
)

// Set by goreleaser at build time
var (
	version = "dev"
	commit  = "none"
)

func main() {
	cmd.SetVersion(version, commit)
	cmd.Execute()
}
