package util

import "strings"

// Plain utility code — no HTTP handlers, routes, or endpoints.
func Normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func Sum(xs []int) int {
	total := 0
	for _, x := range xs {
		total += x
	}
	return total
}
