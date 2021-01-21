terraform {
  required_providers {
    aqua = {
      version = "~> 0.0.1"
      source="aquasec.com/field/aqua"
    }
  }
}

resource "aqua_enforcer_groups" "terraform-eg" {
  group_id = "created_by_terraform"
  description = "Created"
  logical_name = "terraform-eg"
  enforce = false
  gateways = [
    "demo"
  ]
  type = "agent"
  orchestrator {
    type = "kubernetes"
    service_account = "aqua-sa"
    namespace = "aqua"
    master = false
  }
}
