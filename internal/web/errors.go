package web

import "errors"

// Job lifecycle errors returned by the scan manager.
var (
	ErrJobNotFound   = errors.New("scan job not found")
	ErrJobNotRunning = errors.New("scan job is not running")
)
