package utils

import "errors"

var (
	ErrEmptyURL             = errors.New("URL cannot be empty")
	ErrInvalidURL           = errors.New("invalid URL format")
	ErrInvalidScheme        = errors.New("URL scheme must be http or https")
	ErrEmptyHost            = errors.New("URL host cannot be empty")
	ErrLocalhostNotAllowed  = errors.New("localhost URLs are not allowed")
	ErrPrivateIPNotAllowed  = errors.New("private IP addresses are not allowed")
)
