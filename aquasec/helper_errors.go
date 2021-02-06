package aquasec

import (
	"fmt"
)

//NewNotFoundErrorf - godoc
func NewNotFoundErrorf(format string, a ...interface{}) error {
	return fmt.Errorf("%s %s", "Could not find", fmt.Sprintf(format, a...))
}

// //NewNotEmptyOrWhiteSpaceError - godoc
// func NewNotEmptyOrWhiteSpaceError(k string) error {
// 	return fmt.Errorf("expected %q to not be an empty string or whitespace", k)
// }

// //NewInvalidResourceIDError - godoc
// func NewInvalidResourceIDError(resource string, ID string) error {
// 	return fmt.Errorf("Invalid %s ID %s, please check the terraform state file", resource, ID)
// }
