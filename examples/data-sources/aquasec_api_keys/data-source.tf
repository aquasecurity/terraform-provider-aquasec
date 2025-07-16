#Listing of single API Key details
data "aquasec_aqua_api_keys" "single" {
    id = aquasec_aqua_api_key.terraform_api_key.id
}

output "api_key_single_id" {
  value = data.aquasec_aqua_api_keys.single.id
}
output "group_id" {
  value = data.aquasec_aqua_api_keys.single.group_id
}
output "expiration" {
  value = data.aquasec_aqua_api_keys.single.expiration
}
output "permission_ids" {
  value = data.aquasec_aqua_api_keys.single.permission_ids
}     
output "roles" {
  value = data.aquasec_aqua_api_keys.single.roles
}

output "secret" {
  value = aquasec_aqua_api_key.terraform_api_key.secret  //resource.resource_name.secret
  sensitive = true
}

#Listing of all API Keys

data "aquasec_aqua_api_keys" "list" {
    limit = 10
    offset = 0
}

output "api_key_list" {
  value = data.aquasec_aqua_api_keys.list
  sensitive = true
}
