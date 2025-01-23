resource "aquasec_permission_set_saas" "example" {
  name        = "saas_permission_set"
  description = "SaaS Permission Set created by Terraform"
  actions = [
    ###################
    # Account Management
    ###################
    "account_mgmt.groups.read",
    
    ###################
    # Cloud Security
    ###################
    "cspm.cloud_accounts.read",
    
    ###################
    # CNAPP Platform
    ###################
    "cnapp.inventory.read",
    "cnapp.insights.read",
    "cnapp.dashboards.read"
  ]
}

output "permission_set_saas" {
  value = aquasec_permission_set_saas.example
}