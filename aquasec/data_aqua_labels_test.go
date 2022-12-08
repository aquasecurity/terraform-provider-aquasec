package aquasec

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecAquaLabelsDatasource(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	description := "terraform-test"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecAquaLabelsDataSource(name, description),
				Check:  testAccCheckAquasecAquaLabelsDataSourceExists("data.aquasec_aqua_labels.test_aqua_labels"),
			},
		},
	})
}

func testAccCheckAquasecAquaLabelsDataSource(name, description string) string {
	return fmt.Sprintf(`
	resource "aquasec_aqua_label" "new" {
		name = "%s"
		description = "%s"
	}

	data "aquasec_aqua_labels" "test_aqua_labels" {
	}
	`, name, description)

}

func testAccCheckAquasecAquaLabelsDataSourceExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("Id for %s in state", n)
		}

		return nil
	}
}
