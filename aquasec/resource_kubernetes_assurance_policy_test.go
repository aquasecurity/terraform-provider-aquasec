package aquasec

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecKubernetesAssurancePolicy(t *testing.T) {
	t.Parallel()
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	application_scopes := "Global"
	assurance_type := "kubernetes"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_kubernetes_assurance_policy.terraformiap"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKubernetesAssurancePolicy(description, name, assurance_type, application_scopes),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKubernetesAssurancePolicyExists("aquasec_kubernetes_assurance_policy.terraformiap"),
				),
			},
		},
	})
}

func TestAquasecKubernetesAssurancePolicyWithInvalidRego(t *testing.T) {
	description := "Test invalid Rego script handling"
	name := acctest.RandomWithPrefix("terraform-test-invalid-rego") + fmt.Sprintf("-%d", time.Now().Unix())
	application_scopes := "Global"
	assurance_type := "kubernetes"
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testAccCheckKubernetesAssurancePolicyWithInvalidRego(description, name, assurance_type, application_scopes),
				ExpectError: regexp.MustCompile("The script uploaded is not in a correct Rego format|failed creating Assurance Policy|failed modifying Assurance Policy|error message"),
			},
		},
	})
}

func testAccCheckKubernetesAssurancePolicy(description string, name string, assurance_type, application_scopes string) string {
	return fmt.Sprintf(`
	resource "aquasec_kubernetes_assurance_policy" "terraformiap" {
		description = "%s"
		name = "%s"
		assurance_type = "%s"
		application_scopes = [
			"%s"
		]
	}`, description, name, assurance_type, application_scopes)

}

func testAccCheckKubernetesAssurancePolicyWithInvalidRego(description string, name string, assurance_type, application_scopes string) string {
	return fmt.Sprintf(`
	resource "aquasec_kubernetes_assurance_policy" "terraformiap_invalid" {
		description = "%s"
		name = "%s"
		assurance_type = "%s"
		application_scopes = [
			"%s"
		]
		custom_checks {
			name      = "invalid_rego_test"
			script_id = "invalid_rego_test"
			engine    = "rego"
			path      = "invalid_rego_test.rego"
			snippet   = <<-EOT
				package kubernetes.validating.invalid
				# Invalid Rego syntax - missing proper structure
				deny contains res {
					invalid_syntax_here
				}
			EOT
		}
	}`, description, name, assurance_type, application_scopes)
}

func testAccCheckKubernetesAssurancePolicyExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("ID for %s in state", n)
		}

		return nil
	}
}
