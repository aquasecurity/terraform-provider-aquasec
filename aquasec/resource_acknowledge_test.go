package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecAcknowledge(t *testing.T) {

	t.Skip("Skipping acknowledge create test because we need to add image and scan it before we are running the ack tests")

	t.Parallel()
	issues := map[string]interface{}{
		"docker_id":        "sha256:8efcf523c90b0268ffdf05b7a73ab0007332067faaffd816ff9f8e733063d889",
		"image_name":       "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon-k8s-cni@sha256:f310c918ee2b4ebced76d2d64a2ec128dde3b364d1b495f0ae73011f489d474d",
		"issue_name":       "ALAS2-2021-1722",
		"issue_type":       "vulnerability",
		"registry_name":    "Host Images",
		"resource_cpe":     "pkg:/amzn:2:nss-softokn:3.44.0-8.amzn2",
		"resource_name":    "nss-softokn",
		"resource_path":    "",
		"resource_type":    "package",
		"resource_version": "3.44.0-8.amzn2",
	}
	issues2 := map[string]interface{}{
		"docker_id":        "",
		"image_name":       "dta-stg-e2e-cv_persistence:latest",
		"issue_name":       "CVE-2022-1271",
		"issue_type":       "vulnerability",
		"registry_name":    "AC-Registry.172746256356.us-east-2",
		"resource_cpe":     "cpe:/a:gnu:gzip:1.10",
		"resource_name":    "gzip",
		"resource_path":    "/usr/bin/gzip",
		"resource_type":    "executable",
		"resource_version": "1.10",
	}

	description := "Created using Terraform"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_acknowledge.terraformap"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAcknowledge(description, []map[string]interface{}{issues, issues2}),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAcknowledgeExists("aquasec_acknowledge.terraformap"),
				),
			},
			//{
			//	Config: testAccCheckAcknowledge(description, []map[string]interface{}{issues, issues2}),
			//	Check: resource.ComposeTestCheckFunc(
			//		testAccCheckAcknowledgeExists("aquasec_acknowledge.terraformap"),
			//	),
			//},
			// currently no id in acknowledge, so we cant import.
			//{
			//	ResourceName:      "aquasec_acknowledge.terraformap",
			//	ImportState:       true,
			//	ImportStateVerify: false, //TODO: when read set up change to true
			//},
		},
	})
}

func testAccCheckAcknowledge(comment string, issues []map[string]interface{}) string {
	issuesString := ""
	for _, issue := range issues {
		issuesString = issuesString + "\n" + generateIssue(issue)
	}
	x := fmt.Sprintf(`
	resource "aquasec_acknowledge" "terraformap" {
		comment = "%s"
		%s
	}`, comment, issuesString)
	return x
}

func generateIssue(issue map[string]interface{}) string {
	return fmt.Sprintf(`
	issues {
					docker_id = "%s"
					image_name = "%s"
					issue_name = "%s"
					issue_type = "%s"
					registry_name = "%s"
					resource_cpe = "%s"
					resource_name = "%s"
					resource_path = "%s"
					resource_type = "%s"
					resource_version = "%s"
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
	)
}

func testAccCheckAcknowledgeExists(n string) resource.TestCheckFunc {
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
