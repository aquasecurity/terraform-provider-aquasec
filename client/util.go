package client

import (
	"errors"
	"strings"
)

type ErrorResponse struct {
	Message string
	Code    int
}

func getMergedError(errs []error) error {
	var errStrs []string
	for _, err := range errs {
		errStrs = append(errStrs, err.Error())
	}

	return errors.New(strings.Join(errStrs, "; "))
}
