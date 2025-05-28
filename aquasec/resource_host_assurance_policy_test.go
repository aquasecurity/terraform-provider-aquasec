package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecHostAssurancePolicy(t *testing.T) {
    t.Parallel()
    description := "Created using Terraform"
    name := acctest.RandomWithPrefix("terraform-test")
    resourceName := "aquasec_host_assurance_policy.terraformiap"

    resource.Test(t, resource.TestCase{
        PreCheck:     func() { testAccPreCheck(t) },
        Providers:    testAccProviders,
        CheckDestroy: CheckDestroy(resourceName),
        Steps: []resource.TestStep{
            {
                Config: testAccCheckHostAssurancePolicyFull(name),
                Check: resource.ComposeTestCheckFunc(
                    testAccCheckHostAssurancePolicyExists(resourceName),
                    func(s *terraform.State) error {
                        _, ok := s.RootModule().Resources[resourceName]
                        if !ok {
                            return fmt.Errorf("Resource not found")
                        }
                        return nil
					},
                    // Basic attributes
                    resource.TestCheckResourceAttr(resourceName, "name", name),
                    resource.TestCheckResourceAttr(resourceName, "description", description),
                    resource.TestCheckResourceAttr(resourceName, "application_scopes.0", "Global"),
                    
                    // CVSS settings
                    resource.TestCheckResourceAttr(resourceName, "cvss_severity_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "cvss_severity", "critical"),
                    resource.TestCheckResourceAttr(resourceName, "cvss_severity_exclude_no_fix", "true"),
                    
                    // Score settings
                    resource.TestCheckResourceAttr(resourceName, "maximum_score_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "maximum_score", "8"),
                    resource.TestCheckResourceAttr(resourceName, "control_exclude_no_fix", "true"),
                    
                    // Malware settings
                    resource.TestCheckResourceAttr(resourceName, "disallow_malware", "true"),
                    resource.TestCheckResourceAttr(resourceName, "monitored_malware_paths.0", "/tmp"),
                    resource.TestCheckResourceAttr(resourceName, "scan_malware_in_archives", "true"),
                    
                    // CIS benchmarks
                    resource.TestCheckResourceAttr(resourceName, "docker_cis_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "kube_cis_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "linux_cis_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "windows_cis_enabled", "true"),
                    
                    // Enforcement settings
                    resource.TestCheckResourceAttr(resourceName, "audit_on_failure", "true"),
                    resource.TestCheckResourceAttr(resourceName, "fail_cicd", "true"),
                    resource.TestCheckResourceAttr(resourceName, "block_failed", "true"),
                    resource.TestCheckResourceAttr(resourceName, "enforce_excessive_permissions", "true"),
                    
                    // Auto scan settings
                    resource.TestCheckResourceAttr(resourceName, "auto_scan_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "auto_scan_configured", "true"),
                    resource.TestCheckResourceAttr(resourceName, "auto_scan_time.0.iteration_type", "daily"),
                    
                    // Scope settings
                    resource.TestCheckResourceAttr(resourceName, "scope.0.expression", "v1"),
                    resource.TestCheckResourceAttr(resourceName, "scope.0.variables.0.attribute", "os.type"),
                    resource.TestCheckResourceAttr(resourceName, "scope.0.variables.0.value", "linux"),
                    
                    // Labels
                    resource.TestCheckResourceAttr(resourceName, "required_labels_enabled", "true"),
                    resource.TestCheckResourceAttr(resourceName, "required_labels.0.key", "env"),
                    resource.TestCheckResourceAttr(resourceName, "required_labels.0.value", "prod"),

					resource.TestCheckResourceAttr(resourceName, "maximum_score_exclude_no_fix", "true"),
                ),
            },
            {
                ResourceName:      resourceName,
                ImportState:       true,
                ImportStateVerify: true,
            },
        },
    })
}

func testAccCheckHostAssurancePolicyFull(name string) string {
    return fmt.Sprintf(`
resource "aquasec_host_assurance_policy" "terraformiap" {
    name = "%s"
    description = "Created using Terraform"
    application_scopes = ["Global"]

    cvss_severity_enabled = true
    cvss_severity = "critical"
    cvss_severity_exclude_no_fix = true
    
    maximum_score_enabled = true
    maximum_score = 8
    control_exclude_no_fix = true
    
    disallow_malware = true
    monitored_malware_paths = ["/tmp"]
    scan_malware_in_archives = true
    
    docker_cis_enabled = true
    kube_cis_enabled = true
    linux_cis_enabled = true
    windows_cis_enabled = true
    
    audit_on_failure = true
    fail_cicd = true
    block_failed = true
    enforce_excessive_permissions = true
    
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
    
    required_labels_enabled = true
    required_labels {
        key = "env"
        value = "prod"
    }

    vulnerability_exploitability = true
    disallow_exploit_types = ["remote", "local"]
    ignore_base_image_vln = false
    ignored_sensitive_resources = ["/etc/passwd", "/etc/shadow"]
    
    scan_process_memory = true
    scan_windows_registry = true
    
    policy_settings {
        enforce = true
        warn = true
        warning_message = "Policy violation detected"
        is_audit_checked = true
    }

    openshift_hardening_enabled = true
	maximum_score_exclude_no_fix = true
}`, name)
}


func testAccCheckHostAssurancePolicyExists(n string) resource.TestCheckFunc {
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
