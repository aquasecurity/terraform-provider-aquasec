package aquasec

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	resourceName       = "aquasec_permission_set_saas.new"
	maxNameLength      = 20
	initialDescription = "Initial description"
)

var invalidConfigTestCases = []struct {
	name     string
	config   string
	errorMsg string
}{
	{
		name: "missing required name",
		config: `
           resource "aquasec_permission_set_saas" "invalid" {
               description = "test"
           }`,
		errorMsg: "name",
	},
	{
		name: "invalid action",
		config: `
           resource "aquasec_permission_set_saas" "invalid" {
               name = "test"
               actions = ["invalid.action"]
           }`,
		errorMsg: "failed creating SaaS PermissionSet",
	},
}

// testAccPermissionSetActionFixtures follows the server contract by selecting a
// write-capable action advertised for the current tenant. The server requires a
// matching read action whenever write is granted.
func testAccPermissionSetActionFixtures(t *testing.T) ([]string, []string) {
	t.Helper()

	url := os.Getenv("TESTING_URL")
	token := os.Getenv("TESTING_AUTH_TOKEN")
	if url == "" || token == "" {
		t.Fatal("test authentication URL and token must be initialized")
	}

	verifyTLS := !strings.EqualFold(os.Getenv("AQUA_TLS_VERIFY"), "false")
	catalogClient, err := client.NewClientWithTokenAuth(url, "", "", verifyTLS, nil)
	if err != nil {
		t.Fatalf("create permission action catalog client: %v", err)
	}
	catalogClient.SetAuthToken(token)

	catalog, err := catalogClient.GetPermissionSetActions()
	if err != nil {
		t.Fatalf("get tenant permission actions: %v", err)
	}
	if len(catalog.Modules) == 0 {
		t.Fatal("tenant permission action catalog returned no groups")
	}

	dependentActions := make(map[string]struct{}, len(catalog.Dependencies))
	for _, dependency := range catalog.Dependencies {
		dependentActions[dependency.Name] = struct{}{}
	}

	candidate := ""
	for _, group := range catalog.Modules {
		for _, action := range group.Actions {
			if action.Action == "" || !action.HasWriteAccess {
				continue
			}
			if _, hasReadDependencies := dependentActions[action.Action+".read"]; hasReadDependencies {
				continue
			}
			if _, hasWriteDependencies := dependentActions[action.Action+".write"]; hasWriteDependencies {
				continue
			}
			if action.Action == "images" {
				candidate = action.Action
				break
			}
			if candidate == "" {
				candidate = action.Action
			}
		}
		if candidate == "images" {
			break
		}
	}

	if candidate == "" {
		t.Fatal("tenant advertises no independent write-capable permission action")
	}

	readAction := candidate + ".read"
	return []string{readAction}, []string{readAction, candidate + ".write"}
}

func permissionSetActionsConfig(actions []string) string {
	quoted := make([]string, len(actions))
	for i, action := range actions {
		quoted[i] = fmt.Sprintf("%q", action)
	}
	return strings.Join(quoted, ",")
}

// Helper Functions

func testAccCheckAquasecPermissionSetSaas(name, description string, actions []string) string {
	return fmt.Sprintf(`
   resource "aquasec_permission_set_saas" "new" {
       name        = "%s"
       description = "%s"
       actions     = [%s]
   }`, name, description, permissionSetActionsConfig(actions))
}

func testAccCheckAquasecPermissionSetSaasExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("ID for %s in state", n)
		}

		c := testAccProvider.Meta().(*client.Client)
		_, err := c.GetPermissionSetSaas(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error finding permission set %s: %s", rs.Primary.ID, err)
		}

		return nil
	}
}

func testAccPermissionSetSaasDestroy(s *terraform.State) error {
	c := testAccProvider.Meta().(*client.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aquasec_permission_set_saas" {
			continue
		}

		permSet, err := c.GetPermissionSetSaas(rs.Primary.ID)
		if err == nil && permSet != nil {
			return fmt.Errorf("permission set %q still exists", rs.Primary.ID)
		}
		if err != nil && !strings.Contains(err.Error(), "404") {
			return fmt.Errorf("check permission set %q destruction: %w", rs.Primary.ID, err)
		}
	}

	return nil
}

// Test Functions

func TestAquasecPermissionSetSaasManagement(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
	description := "Permission set created by Terraform acceptance test"
	_, extendedTestActions := testAccPermissionSetActionFixtures(t)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, description, extendedTestActions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetSaasExists(resourceName),
				),
			},
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, "Updated "+description, extendedTestActions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetSaasExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated "+description),
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

func TestAquasecPermissionSetSaasInvalidConfig(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	for _, tc := range invalidConfigTestCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:     func() { testAccPreCheck(t) },
				Providers:    testAccProviders,
				CheckDestroy: testAccPermissionSetSaasDestroy,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: regexp.MustCompile(tc.errorMsg),
					},
				},
			})
		})
	}
}

func TestAquasecPermissionSetSaasWithExternalChanges(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
	defaultTestActions, extendedTestActions := testAccPermissionSetActionFixtures(t)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			{
				Config:             testAccCheckAquasecPermissionSetSaas(name, initialDescription, defaultTestActions),
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetSaasExists(resourceName),
					func(s *terraform.State) error {
						t.Logf("[INFO] Permission Set '%s' created via Terraform with description: '%s'", name, initialDescription)
						provider := testAccProvider.Meta().(*client.Client)
						permSet := &client.PermissionSetSaas{
							Name:        name,
							Description: "Modified via API",
							Actions:     defaultTestActions,
						}
						if err := provider.UpdatePermissionSetSaas(permSet); err != nil {
							return err
						}
						t.Logf("[INFO] Permission Set '%s' modified externally via API to description: 'Modified via API'", name)
						return nil
					},
				),
			},
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, initialDescription, defaultTestActions),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", initialDescription),
					func(s *terraform.State) error {
						provider := testAccProvider.Meta().(*client.Client)
						permSet, err := provider.GetPermissionSetSaas(name)
						if err != nil {
							return err
						}
						t.Logf("[INFO] Permission Set '%s' reverted by Terraform to match state - description: '%s'", name, permSet.Description)
						return nil
					},
				),
			},
			{
				Config:             testAccCheckAquasecPermissionSetSaas(name, initialDescription, extendedTestActions),
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						t.Logf("[INFO] Running terraform plan to verify no changes needed for Permission Set '%s'", name)
						t.Logf("[INFO] Terraform updating Permission Set '%s' actions via configuration", name)
						return nil
					},
				),
			},
		},
	})
}

func TestAquasecPermissionSetSaasReadErrorHandling(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
	defaultTestActions, _ := testAccPermissionSetActionFixtures(t)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, "test description", defaultTestActions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetSaasExists(resourceName),
					// Delete the permission set outside of Terraform
					func(s *terraform.State) error {
						client := testAccProvider.Meta().(*client.Client)
						return client.DeletePermissionSetSaas(name)
					},
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAquasecPermissionSetSaasUpdateErrorHandling(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
	defaultTestActions, _ := testAccPermissionSetActionFixtures(t)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, "initial", defaultTestActions),
			},
			{
				Config:      testAccCheckAquasecPermissionSetSaas(name, "updated", append(append([]string{}, defaultTestActions...), "invalid.action")),
				ExpectError: regexp.MustCompile("Error: failed updating SaaS PermissionSet"),
			},
		},
	})
}

func TestAquasecPermissionSetSaasValues(t *testing.T) {
	if !isSaasEnv() {
		t.Skip("Skipping permission set test - not a SaaS environment")
	}

	name := acctest.RandomWithPrefix("tf-test")[:maxNameLength]
	description := "Created using Terraform"
	resourceName := "aquasec_permission_set_saas.new"
	_, extendedTestActions := testAccPermissionSetActionFixtures(t)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccPermissionSetSaasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckAquasecPermissionSetSaas(name, description, extendedTestActions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecPermissionSetSaasExists(resourceName),
					// Verify all attributes match exactly what was set
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", description),
					// Verify each action in the actions list
					resource.TestCheckResourceAttr(resourceName, "actions.#", fmt.Sprintf("%d", len(extendedTestActions))),
					resource.TestCheckResourceAttr(resourceName, "actions.0", extendedTestActions[0]),
					resource.TestCheckResourceAttr(resourceName, "actions.1", extendedTestActions[1]),
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
