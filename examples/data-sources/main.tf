terraform {
  required_providers {
    aquasec = {
      //      version = "0.8.41"
      source = "aquasecurity/aquasec"
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

output "enforcergroups" {
  value = data.aquasec_enforcer_groups.testegdata
}

data "aquasec_image" "test" {
  registry   = "Docker Hub"
  repository = "elasticsearch"
  tag        = "7.10.1"
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


data "aquasec_gateways" "testgateways" {
}

output "gateways" {
  value = data.aquasec_gateways.testgateways
}

data "aquasec_image_assurance_policy" "default-iap" {
  name = "DTA"
}

output "image-assurance" {
  value = data.aquasec_image_assurance_policy.default-iap
}

data "aquasec_permissions_sets" "testpermissionsset" {}

output "permissions_sets" {
  value = data.aquasec_permissions_sets.testpermissionsset
}

output "permissions_sets_names" {
  value = data.aquasec_permissions_sets.testpermissionsset[*].permissions_sets[*].name
}


data "aquasec_host_assurance_policy" "default-hap" {
  name = "Default"
}

output "host-assurance" {
  value = data.aquasec_host_assurance_policy.default-hap
}

data "aquasec_function_assurance_policy" "default-fap" {
  name = "Default"
}

output "function-assurance" {
  value = data.aquasec_function_assurance_policy.default-fap
}

data "aquasec_application_scope" "default" {
  name = "Global"
}

output "scopes" {
  value = data.aquasec_application_scope.default
}
