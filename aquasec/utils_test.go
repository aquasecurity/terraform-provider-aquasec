package aquasec

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func CheckDestroy(ResourceName string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		for _, rs := range s.RootModule().Resources {
			if rs.Type != ResourceName {
				continue
			}

			if rs.Primary.ID != "" {
				return fmt.Errorf("Object %q still exists", rs.Primary.ID)
			}
			return nil
		}
		return nil
	}
}
