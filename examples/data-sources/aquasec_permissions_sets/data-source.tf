data "aquasec_permissions_sets" "testpermissionsset" {}

output "permissions_sets" {
  value = data.aquasec_permissions_sets.testpermissionsset
}

output "permissions_sets_names" {
  value = data.aquasec_permissions_sets.testpermissionsset[*].permissions_sets[*].name
}