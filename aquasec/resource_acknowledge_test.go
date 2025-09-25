package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecAcknowledge(t *testing.T) {
	// Define the issue to be acknowledged
	issue := map[string]interface{}{
		"docker_id":        "",
		"image_name":       "nginx:alpine3.18",
		"issue_name":       "CVE-2024-45492",
		"issue_type":       "vulnerability",
		"registry_name":    "Docker Hub",
		"resource_cpe":     "pkg:/alpine:3.18.6:libexpat:2.6.2-r0",
		"resource_name":    "libexpat",
		"resource_path":    "",
		"resource_type":    "package",
		"resource_version": "2.6.2-r0",
		"expiration_days":  60,
	}

	// Define the comment for the acknowledgment
	comment := "Created using Terraform"

	// Run the acceptance test
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_acknowledge.acknowledge"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAcknowledgeFullConfig(comment, []map[string]interface{}{issue}),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAcknowledgeExists("aquasec_acknowledge.acknowledge"),
					testAccCheckImageExists("aquasec_image.example_aquasec_image"),
				),
			},
		},
	})
}

// testAccCheckAcknowledgeFullConfig returns a full HCL config including registry, image, and acknowledge
func testAccCheckAcknowledgeFullConfig(comment string, issues []map[string]interface{}) string {
	// Generate the issues block
	issuesString := ""
	for _, issue := range issues {
		issuesString += "\n" + generateIssue(issue)
	}

	// Return the full HCL configuration
	return fmt.Sprintf(`

resource "aquasec_image" "example_aquasec_image" {
  registry   = "Docker Hub"
  repository = "nginx"
  tag        = "alpine3.18"

    provisioner "local-exec" {
    command = <<EOT
      sleep 60
    EOT
  }
}

resource "aquasec_acknowledge" "acknowledge" {
  comment = "%s"
  %s
  depends_on = [aquasec_image.example_aquasec_image]
}
`, comment, issuesString)
}

// generateIssue returns the HCL representation of an issue
func generateIssue(issue map[string]interface{}) string {
	return fmt.Sprintf(`
  issues {
    docker_id        = "%s"
    image_name       = "%s"
    issue_name       = "%s"
    issue_type       = "%s"
    registry_name    = "%s"
    resource_cpe     = "%s"
    resource_name    = "%s"
    resource_path    = "%s"
    resource_type    = "%s"
    resource_version = "%s"
    expiration_days  = %d
  }`, issue["docker_id"],
		issue["image_name"],
		issue["issue_name"],
		issue["issue_type"],
		issue["registry_name"],
		issue["resource_cpe"],
		issue["resource_name"],
		issue["resource_path"],
		issue["resource_type"],
		issue["resource_version"],
		issue["expiration_days"].(int),
	)
}

// testAccCheckAcknowledgeExists checks if the acknowledge resource exists
func testAccCheckAcknowledgeExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("%s not found in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("ID not set for %s", n)
		}
		return nil
	}
}

// testAccCheckImageExists checks if the image resource exists
func testAccCheckImageExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("%s not found in state", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("ID not set for image %s", n)
		}
		return nil
	}
}
