// The module path is intentionally github.com/QuantumNous/new-api: this repo is
// a self-contained, buildable subset of the QuantumNous/new-api module (the SGX
// relay-core enclave + its client verifier), so the import paths resolve exactly
// as they do in the upstream project. The enclave's dependency closure imports
// ONLY the Go standard library plus the three pure packages in this repo, so no
// `require` directives are needed and `go build ./cmd/relay-core` fetches
// nothing from the network.
module github.com/QuantumNous/new-api

go 1.25.1
