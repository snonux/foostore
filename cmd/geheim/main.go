// main is the entry point for the geheim binary.
// It delegates all logic to the cli package and exits with the returned code.
package main

import (
	"os"

	"codeberg.org/snonux/geheim/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
