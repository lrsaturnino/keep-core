//go:build tools

// tools.go: Build-time dependencies required for Ethereum bindings generation
// These are imported to ensure they remain in go.mod and go.sum even though
// they're not directly used in the runtime code.
package tools

import (
	_ "github.com/ferranbt/fastssz"
	_ "github.com/graph-gophers/graphql-go"
	_ "github.com/influxdata/influxdb-client-go/v2"
	_ "github.com/influxdata/influxdb1-client"
	_ "github.com/peterh/liner"
	// go-ruleguard/dsl is used only by .golangci-ruleguard.rules.go (behind the
	// `ruleguard` build tag) and enforced via gocritic in .golangci.yml; pinned
	// here so CI can resolve it and `go mod tidy` does not drop it.
	_ "github.com/quasilyte/go-ruleguard/dsl"
)
