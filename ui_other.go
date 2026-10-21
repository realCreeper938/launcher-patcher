//go:build !windows

package main

import (
	"fmt"
	"os"
)

func runUI() {
	fmt.Fprintln(os.Stderr, errUINotAvailable)
	os.Exit(1)
}
