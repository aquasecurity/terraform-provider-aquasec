package aquasec

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecDataSourceLogManagement(t *testing.T) {
	//t.Skip("Skipping Log Management Data Source test")
	t.Parallel()
	name := "CloudWatch"
	key := os.Getenv("AWS_SECRET_ACCESS_KEY")
	keyid := os.Getenv("AWS_ACCESS_KEY_ID")

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckLogManagementDataSource(name, key, keyid),
				Check: resource.ComposeTestCheckFunc(
					testAccPrintAllLogManagements(),
				),
			},
		},
	})
}

func testAccCheckLogManagementDataSource(name, key, keyid string) string {
	return fmt.Sprintf(`
 resource "aquasec_log_management" "logmanagement" {
   name   = "%s"
   region = "us-west-1"
   loggroup = "terraform-provider-log-group"
   key    = "%s"
   keyid  = "%s"
   enable = true
`, name, key, keyid) + `
 }

  data "aquasec_log_managements" "all" {
  }`
}

func testAccPrintAllLogManagements() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		prov, ok := testAccProviders["aquasec"]
		if !ok || prov == nil {
			return fmt.Errorf("test provider 'aquasec' not found")
		}

		// provider.Meta() holds the client (ensure your test provider sets Meta properly)
		cli, ok := prov.Meta().(*client.Client)
		if !ok || cli == nil {
			return fmt.Errorf("failed to get client from provider meta")
		}

		logMgmt, err := cli.GetLogManagements()
		if err != nil {
			return fmt.Errorf("GetLogManagements() error: %v", err)
		}

		// pretty print JSON to stdout (visible in `go test -v` logs)
		out, _ := json.MarshalIndent(logMgmt, "", "  ")
		fmt.Printf("\n==== Full LogManagements JSON ====\n%s\n=================================\n", string(out))
		return nil
	}
}

func testAccCheckLogMgmtContains(n, expectedName string, expectedAttrs map[string]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("%s not found", n)
		}

		// find all key prefixes that refer to providers
		keys := rs.Primary.Attributes

		// Loop through all attributes and find providers by detecting `<provider>.name`
		providerNames := map[string]string{} // map[keyPrefix]name
		for k, v := range keys {
			if strings.HasSuffix(k, ".name") {
				prefix := strings.TrimSuffix(k, ".name")
				providerNames[prefix] = v
			}
		}

		// Ensure expected provider exists
		var prefix string
		for p, v := range providerNames {
			if v == expectedName {
				prefix = p
				break
			}
		}
		if prefix == "" {
			return fmt.Errorf("provider %q not found in data source", expectedName)
		}

		// validate attributes under this prefix
		for attr, want := range expectedAttrs {
			key := fmt.Sprintf("%s.%s", prefix, attr)
			got := keys[key]

			if got != want {
				return fmt.Errorf("provider %q: expected %s=%s, got %s", expectedName, attr, want, got)
			}
		}

		return nil
	}
}
