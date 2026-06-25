package aquasec

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecresourceAnyRegistry(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("terraform-test")
	url := "https://docker.io"
	rtype := "HUB"
	username := ""
	password := ""
	autopull := false
	scanner_type := "any"
	description := "Terrafrom-test"
	option := "status"
	value := "Connected"
	force_ootb := false
	force_save := false
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_integration_registry.new"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecRegistry(name, url, rtype, username, password, autopull, scanner_type, description, option, value, force_ootb, force_save),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecRegistryExists("aquasec_integration_registry.new"),
				),
			},
			{
				ResourceName:            "aquasec_integration_registry.new",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"prefixes", "scanner_name", "last_updated"}, //TODO: implement read prefixes
			},
		},
	})
}

func testAccCheckAquasecRegistry(name string, url string, rtype string, username string, password string, autopull bool, scanner_type string, description string, option string, value string, force_ootb bool, force_save bool) string {
	return fmt.Sprintf(`
	resource "aquasec_integration_registry" "new" {
		name = "%s"
		url = "%s"
		type = "%s"
		username = "%s"
		password = "%s"
		auto_pull = "%v"
		scanner_type = "%s"
		description = "%s"

		options {
			option = "%s"
			value = "%s"
		}

		force_ootb = "%v"
		force_save = "%v"

	}`, name, url, rtype, username, password, autopull, scanner_type, description, option, value, force_ootb, force_save)

}

func testAccCheckAquasecRegistryExists(n string) resource.TestCheckFunc {
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

func TestExpandRegistryOptions(t *testing.T) {
	t.Parallel()

	options := []interface{}{
		map[string]interface{}{"option": registryOptionARNRole, "value": "old-role"},
		map[string]interface{}{"option": registryOptionSTSExternalID, "value": "old-external-id"},
		map[string]interface{}{"option": "TestImagePull", "value": "nginx:latest"},
	}

	got := expandRegistryOptions(options, "arn:aws:iam::123456789012:role/aqua-ecr-read", "my-external-id")
	want := []client.Options{
		{Option: "TestImagePull", Value: "nginx:latest"},
		{Option: registryOptionARNRole, Value: "arn:aws:iam::123456789012:role/aqua-ecr-read"},
		{Option: registryOptionSTSExternalID, Value: "my-external-id"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected options diff\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDetectRegistryConnectionType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		registryType string
		username     string
		password     string
		options      []client.Options
		want         string
	}{
		{
			name:         "aws access delegation",
			registryType: "AWS",
			options: []client.Options{
				{Option: registryOptionARNRole, Value: "arn:aws:iam::123456789012:role/aqua-ecr-read"},
			},
			want: registryConnectionTypeAccessDelegation,
		},
		{
			name:         "aws credentials",
			registryType: "AWS",
			username:     "AKIA...",
			password:     "secret",
			want:         registryConnectionTypeCredentials,
		},
		{
			name:         "non aws registry",
			registryType: "HUB",
			username:     "user",
			password:     "secret",
			want:         "",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := detectRegistryConnectionType(tc.registryType, tc.username, tc.password, tc.options)
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestValidateRegistryConnectionType(t *testing.T) {
	t.Parallel()

	if err := validateRegistryConnectionType("AWS", registryConnectionTypeAccessDelegation, "", ""); err == nil {
		t.Fatal("expected validation error for missing role_arn")
	}

	if err := validateRegistryConnectionType("HUB", registryConnectionTypeAccessDelegation, "arn:aws:iam::123456789012:role/aqua-ecr-read", ""); err == nil {
		t.Fatal("expected validation error for non-AWS registry")
	}

	if err := validateRegistryConnectionType("AWS", registryConnectionTypeAccessDelegation, "arn:aws:iam::123456789012:role/aqua-ecr-read", ""); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if err := validateRegistryConnectionType("AWS", "", "", "my-external-id"); err == nil {
		t.Fatal("expected validation error for external_id without role_arn")
	}
}
