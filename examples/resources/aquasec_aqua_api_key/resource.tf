resource "aquasec_aqua_api_key" "terraform_api_key" {
  description = "Terraform-managed API key"
  //Roles that need to be assigned to the API Key
  roles = [
    "Global_Role"
  ]
  //Expiry of the API Key is in days
  expiration = 365
  //List of IP addresses the API key can be used from.
  ip_addresses = [
    "1.1.1.1"
  ]
  //The group ID that is associated with the API key.
  group_id = 41902
  //List of permission IDs for the API key, if empty the API key has global admin permissions.
  permission_ids = [
    36,
    35
  ]
  //Whether the apikey is enabled or not.
  enabled = true
}
