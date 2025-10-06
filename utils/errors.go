package utils

import "errors"

var (
	ErrEmptyURL             = errors.New("URL cannot be empty")
	ErrInvalidURL           = errors.New("invalid URL format")
	ErrInvalidScheme        = errors.New("URL scheme must be http or https")
	ErrEmptyHost            = errors.New("URL host cannot be empty")
	ErrLocalhostNotAllowed  = errors.New("localhost URLs are not allowed")
	ErrPrivateIPNotAllowed  = errors.New("private IP addresses are not allowed")
	ErrSlugTooShort         = errors.New("custom slug must be at least 3 characters")
	ErrSlugTooLong          = errors.New("custom slug must be at most 64 characters")
	ErrSlugInvalidFormat    = errors.New("custom slug can only contain letters, numbers, hyphens, and underscores")
	ErrSlugInvalidStart     = errors.New("custom slug must start with a letter or number")
	ErrSlugInvalidEnd       = errors.New("custom slug must end with a letter or number")
	ErrSlugReserved         = errors.New("custom slug is reserved for system use")
	ErrSlugPureNumber       = errors.New("custom slug cannot be a pure number")
)
