package aquasec

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func newTestImage() client.Image {
	return client.Image{
		Registry:   acctest.RandomWithPrefix("terraform-test"),
		Repository: "alpine",
		Tag:        "3.4",
	}
}

func TestResourceAquasecImageCreate(t *testing.T) {
	//t.Parallel()
	image := newTestImage()
	rootRef := imageResourceRef("test")
	option := "status"
	value := "Connected"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_image.test"),
		Steps: []resource.TestStep{
			{
				Config: getImageResource(&image, option, value),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttrSet(rootRef, "scan_status"),
					resource.TestCheckResourceAttrSet(rootRef, "disallowed"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
				),
			},
			{
				ResourceName:      "aquasec_image.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"scan_date", "scan_status", "scan_error", "vulnerabilities",
					"architecture", "created", "digest", "docker_id", "docker_version",
					"environment_variables.#", "histories.#", "assurance_checks_performed.#",
					"assurance_checks_performed.0.*", "assurance_checks_performed.1.*",
					"os", "os_version", "image_type",
					"medium_vulnerabilities", "high_vulnerabilities", "total_vulnerabilities",
				},
			},
		},
	})
}

func TestResourceAquasecImageAllowAndBlock(t *testing.T) {
	image := client.Image{
		Registry:   "Docker Hub",
		Repository: "alpine",
		Tag:        "3.24.1",
	}
	rootRef := imageResourceRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_image.test"),
		Steps: []resource.TestStep{
			{
				Config: getExistingImageResource(&image),
				Check:  testAccWaitForImageScan(&image),
			},
			{
				Config: getImageResourceAllow(&image, "This image is whitelisted from terraform test."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "whitelisted", "true"),
					resource.TestCheckResourceAttr(rootRef, "blacklisted", "false"),
					resource.TestCheckResourceAttr(rootRef, "permission_comment", "This image is whitelisted from terraform test."),
				),
			},
			{
				Config: getImageResourceBlock(&image, "This image is blacklisted from terraform test."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "blacklisted", "true"),
					resource.TestCheckResourceAttr(rootRef, "whitelisted", "false"),
					resource.TestCheckResourceAttr(rootRef, "permission_comment", "This image is blacklisted from terraform test."),
				),
			},
		},
	})
}

func testAccWaitForImageScan(image *client.Image) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		c := testAccProvider.Meta().(*client.Client)
		imageURL := fmt.Sprintf("%s/%s/%s", image.Registry, image.Repository, image.Tag)

		return resource.RetryContext(context.Background(), 5*time.Minute, func() *resource.RetryError {
			scannedImage, err := c.GetImage(imageURL)
			if err != nil {
				return resource.RetryableError(err)
			}

			switch scannedImage.ScanStatus {
			case "finished":
				return nil
			case "failed":
				return resource.NonRetryableError(fmt.Errorf("image scan failed: %s", scannedImage.ScanError))
			default:
				return resource.RetryableError(fmt.Errorf("image scan status is %q", scannedImage.ScanStatus))
			}
		})
	}
}

func imageResourceRef(name string) string {
	return fmt.Sprintf("aquasec_image.%s", name)
}

func getImageResource(image *client.Image, option, value string) string {
	return getRegistry(image.Registry, option, value) + fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry = aquasec_integration_registry.demo.id
		repository = "%s"
		tag = "%s"

	}`, image.Repository, image.Tag)
}

func getExistingImageResource(image *client.Image) string {
	return fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry   = "%s"
		repository = "%s"
		tag        = "%s"
	}
`, image.Registry, image.Repository, image.Tag)
}

func getImageResourceAllow(image *client.Image, comment string) string {
	return fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry   = "%s"
		repository = "%s"
		tag        = "%s"
		allow_image = true
		permission_modification_comment = "%s"
	}
`, image.Registry, image.Repository, image.Tag, comment)
}

func getImageResourceBlock(image *client.Image, comment string) string {
	return fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry   = "%s"
		repository = "%s"
		tag        = "%s"
		block_image = true
		permission_modification_comment = "%s"
	}
`, image.Registry, image.Repository, image.Tag, comment)
}

func getRegistry(name, option, value string) string {
	return fmt.Sprintf(`
	resource "aquasec_integration_registry" "demo" {
		name = "%s"
		type = "HUB"
		scanner_type = "any"

		options {
			option = "%s"
			value = "%s"
		}
	}
`, name, option, value)
}
