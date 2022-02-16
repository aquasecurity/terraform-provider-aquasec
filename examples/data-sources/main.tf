terraform {
  required_providers {
    aquasec = {
      //      version = "0.8.6"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
  username = "admin"
  aqua_url = "https://aquaurl.com"
  password = "@password"
}

data "aquasec_users" "testusers" {
}

output "name" {
  value = data.aquasec_users.testusers
}

data "aquasec_integration_registry" "testregistries" {
  name = "samplename"
}

output "registries" {
  value = data.aquasec_integration_registry.testregistries
}

data "aquasec_service" "test-svc" {
  name = "test-svc"
}

output "service" {
  value = data.aquasec_service.test-svc
}

data "aquasec_enforcer_groups" "testegdata" {
	group_id = "default"
}

output "enforcergroups"{
  value = data.aquasec_enforcer_groups.testegdata
}

data "aquasec_image" "test" {
  registry = "Docker Hub"
  repository = "elasticsearch"
  tag = "7.10.1"
}

output "image" {
  value = data.aquasec_image.test
}

data "aquasec_container_runtime_policy" "test" {
  name = "test-container-runtime-policy"
}

output "test-crp" {
  value = data.aquasec_container_runtime_policy.test
}

data "aquasec_function_runtime_policy" "test" {
  name = "test-function-runtime-policy"
}

output "test-frp" {
  value = data.aquasec_function_runtime_policy.test
}

data "aquasec_host_runtime_policy" "test" {
  name = "test-host-runtime-policy"
}

output "test-hrp" {
  value = data.aquasec_host_runtime_policy.test
}

data "aquasec_assurance_policy" "default" {
    name = "DTA"
}

output "images" {
  value = data.aquasec_assurance_policy.default
}