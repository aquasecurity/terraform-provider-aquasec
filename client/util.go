package client

import (
	"github.com/pkg/errors"
)

type ErrorResponse struct {
	Message string
	Code    int
}

func getMergedError(errs []error) error {
	var mergedErr error
	for _, err := range errs {
		mergedErr = errors.Wrap(mergedErr, err.Error())
	}

	return mergedErr
}
