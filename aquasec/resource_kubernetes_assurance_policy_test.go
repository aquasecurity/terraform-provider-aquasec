package aquasec

import (
	"fmt"
	"regexp"
	"testing"

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

func TestAquasecKubernetesAssurancePolicyRegoValidation(t *testing.T) {
	t.Parallel()
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test-rego")
	application_scopes := "Global"
	assurance_type := "kubernetes"
	
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_kubernetes_assurance_policy.terraformiap"),
		Steps: []resource.TestStep{
			{
				Config:      testAccCheckKubernetesAssurancePolicyWithInvalidRego(description, name, assurance_type, application_scopes),
				ExpectError: regexp.MustCompile("rego validation error"),
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
	resource "aquasec_kubernetes_assurance_policy" "terraformiap" {
		description = "%s"
		name = "%s"
		assurance_type = "%s"
		application_scopes = [
			"%s"
		]
		custom_checks {
			name      = "invalid_rego"
			script_id = "invalid_rego"
			engine    = "rego"
			path      = "invalid_rego.rego"
			snippet   = <<-EOT
				package kubernetes.validating.ingress.KSV0212
				deny contains res {
					input_host != ""
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
