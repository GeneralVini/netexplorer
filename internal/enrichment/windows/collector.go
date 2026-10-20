package windows

import _ "embed"

// Collector is a read-only PowerShell export script served as an attachment or sent to a Windows SSH peer.
//
//go:embed collect.ps1
var Collector string
