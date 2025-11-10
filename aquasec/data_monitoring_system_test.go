package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecMonitoringSystemDataSourceAny(t *testing.T) {
	t.Parallel()

	name := "Prometheus"
	msType := "prometheus"
	token := "tf-acc-token"
	enabled := true
	interval := 30

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccMonitoringSystemDataSourceAny(name, msType, token, enabled, interval),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAquasecMonitoringSystemDataSourceExists("data.aquasec_monitoring_systems.test_ms"),
					resource.TestCheckResourceAttr("data.aquasec_monitoring_systems.test_ms", "monitors.0.name", name),
					resource.TestCheckResourceAttr("data.aquasec_monitoring_systems.test_ms", "monitors.0.type", msType),
					resource.TestCheckResourceAttr("data.aquasec_monitoring_systems.test_ms", "monitors.0.enabled", fmt.Sprintf("%t", enabled)),
					resource.TestCheckResourceAttr("data.aquasec_monitoring_systems.test_ms", "monitors.0.interval", fmt.Sprintf("%d", interval))),
			},
		},
	})
}

func testAccMonitoringSystemDataSourceAny(name, msType, token string, enabled bool, interval int) string {
	return fmt.Sprintf(`
resource "aquasec_monitoring_system" "any" {
  name     = "%s"
  type     = "%s"
  token    = "%s"
  enabled  = %t
  interval = %d
}

data "aquasec_monitoring_systems" "test_ms" {
  depends_on = [
    aquasec_monitoring_system.any
  ]
}
`, name, msType, token, enabled, interval)
}

func testAccCheckAquasecMonitoringSystemDataSourceExists(n string) resource.TestCheckFunc {
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
