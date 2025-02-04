package aquasec

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccDataSourceHostAssurancePolicy_Basic(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	description := "Created using Terraform"
	dataSourceName := "data.aquasec_host_assurance_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceHostAssurancePolicyBasic(name, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "name", name),
					resource.TestCheckResourceAttr(dataSourceName, "description", description),
					resource.TestCheckResourceAttr(dataSourceName, "application_scopes.0", "Global"),
					resource.TestCheckResourceAttr(dataSourceName, "assurance_type", "host"),
					resource.TestCheckResourceAttrSet(dataSourceName, "author"),
					// Verify basic settings
					resource.TestCheckResourceAttr(dataSourceName, "linux_cis_enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "windows_cis_enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "maximum_score_enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "maximum_score", "8"),
					// Verify malware settings
					resource.TestCheckResourceAttr(dataSourceName, "disallow_malware", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "monitored_malware_paths.0", "/tmp"),
				),
			},
		},
	})
}

func TestAccDataSourceHostAssurancePolicy_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testAccDataSourceHostAssurancePolicyNonExistent(),
				ExpectError: regexp.MustCompile(`.*nonexistent-policy: assurance policy doesn't exist.*`),
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						_, ok := s.RootModule().Resources["data.aquasec_host_assurance_policy.test"]
						if ok {
							return fmt.Errorf("data source should not exist")
						}
						return nil
					},
				),
			},
		},
	})
}

func testAccDataSourceHostAssurancePolicyBasic(name, description string) string {
	return fmt.Sprintf(`
resource "aquasec_host_assurance_policy" "test" {
	name = "%s"
	description = "%s"
	application_scopes = ["Global"]

	linux_cis_enabled = true
	windows_cis_enabled = true
	
	maximum_score_enabled = true
	maximum_score = 8
	
	disallow_malware = true
	monitored_malware_paths = ["/tmp"]
}

data "aquasec_host_assurance_policy" "test" {
	name = aquasec_host_assurance_policy.test.name
}
`, name, description)
}

func testAccDataSourceHostAssurancePolicyNonExistent() string {
	return `
data "aquasec_host_assurance_policy" "test" {
	name = "nonexistent-policy"
}
`
}

func TestAccDataSourceHostAssurancePolicy_FullSettings(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	dataSourceName := "data.aquasec_host_assurance_policy.full"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceHostAssurancePolicyFull(name),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Basic attributes
					resource.TestCheckResourceAttr(dataSourceName, "name", name),
					resource.TestCheckResourceAttr(dataSourceName, "assurance_type", "host"),
					resource.TestCheckResourceAttr(dataSourceName, "application_scopes.0", "Global"),

					// Security controls
					resource.TestCheckResourceAttr(dataSourceName, "docker_cis_enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "kube_cis_enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "openshift_hardening_enabled", "true"),

					// Malware settings
					resource.TestCheckResourceAttr(dataSourceName, "scan_malware_in_archives", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "scan_process_memory", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "scan_windows_registry", "true"),

					// Auto scan settings
					resource.TestCheckResourceAttr(dataSourceName, "auto_scan_enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "auto_scan_configured", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "auto_scan_time.0.iteration_type", "daily"),

					// Scope settings
					resource.TestCheckResourceAttr(dataSourceName, "scope.0.variables.0.attribute", "os.type"),
					resource.TestCheckResourceAttr(dataSourceName, "scope.0.variables.0.value", "linux"),

					// Policy settings
					resource.TestCheckResourceAttr(dataSourceName, "policy_settings.0.enforce", "true"),
					resource.TestCheckResourceAttr(dataSourceName, "policy_settings.0.warn", "true"),
				),
			},
		},
	})
}

func testAccDataSourceHostAssurancePolicyFull(name string) string {
	return fmt.Sprintf(`
resource "aquasec_host_assurance_policy" "full" {
	name = "%s"
	description = "Created using Terraform"
	application_scopes = ["Global"]

	docker_cis_enabled = true
	kube_cis_enabled = true
	openshift_hardening_enabled = true

	scan_malware_in_archives = true
	scan_process_memory = true
	scan_windows_registry = true
	disallow_malware = true
	monitored_malware_paths = ["/tmp"]

	auto_scan_enabled = true
	auto_scan_configured = true
	auto_scan_time {
		iteration_type = "daily"
		time = "2024-01-01T00:00:00Z"
	}

	scope {
		expression = "v1"
		variables {
			attribute = "os.type"
			value = "linux"
		}
	}

	policy_settings {
		enforce = true
		warn = true
		warning_message = "Policy violation detected"
		is_audit_checked = true
	}
}

data "aquasec_host_assurance_policy" "full" {
	name = aquasec_host_assurance_policy.full.name
}
`, name)
}
