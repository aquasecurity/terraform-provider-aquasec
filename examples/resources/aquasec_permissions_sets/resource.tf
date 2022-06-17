resource "aquasec_permissions_sets" "my_terraform_perm_set" {
  name        = "my_terraform_perm_set"
  description = "Test Permissions Sets created by Terraform"
  author      = "system"
  ui_access   = true
  is_super    = false
  actions = [
    #################
    # Policies
    #################
    # Assurance Policies
    "acl_policies.read",
    "acl_policies.write",
    # Image Profiles
    "image_profiles.read",
    # "image_profiles.write",          # Not supported yet - only via WebGUI
    # Firewall Policies
    "network_policies.read",
    # "network_policies.write",        # Not supported yet - only via WebGUI
    # Runtime Policies
    "runtime_policies.read",
    "runtime_policies.write",
    # User Access Control Policies
    "image_assurance.read",
    "image_assurance.write",

    #################
    # Assets
    #################
    # Dashboard
    "dashboard.read",
    # "dashboard.write",               # Not supported yet - only via WebGUI
    # Risk Explorer
    "risk_explorer.read",
    # Images
    "images.read",
    # "images.write",                  # Not supported yet - only via WebGUI
    # Host Images
    "risks.host_images.read",
    # "risks.host_images.write",       # Not supported yet - only via WebGUI
    # Functions
    "functions.read",
    # "functions.write",               # Not supported yet - only via WebGUI
    # Enforcers
    "enforcers.read",
    # "enforcers.write",               # Not supported yet - only via WebGUI
    # Containers
    "containers.read",
    # Services
    "services.read",
    # "services.write",                # Not supported yet - only via WebGUI
    # Infrastructure
    "infrastructure.read",
    # "infrastructure.write",          # Not supported yet - only via WebGUI

    #################
    # Compliance
    #################
    # Vulnerabilities
    "risks.vulnerabilities.read",
    "risks.vulnerabilities.write",
    # CIS Benchmarks
    "risks.benchmark.read",
    # "risks.benchmark.write",         # Not supported yet - only via WebGUI

    #################
    # System
    #################
    # Audit Events
    "audits.read",
    # Secrets
    "secrets.read",
    # "secrets.write",                 # Not supported yet - only via WebGUI
    # Settings
    "settings.read",
    # "settings.write",                # Not supported yet - only via WebGUI
    # Integrations
    "integrations.read",
    # "integrations.write",            # Not supported yet - only via WebGUI
    # Image Registry Integrations
    "registries_integrations.read",
    # "registries_integrations.write", # Not supported yet - only via WebGUI
    # Scanner CLI                      # Not supported yet - only via WebGUI
    # Gateways
    "gateways.read",
    # "gateways.write",                # Not supported yet - only via WebGUI
    # Consoles
    "consoles.read",
    # Webhook authorization API
    "web_hook.read",
    # Incidents
    "incidents.read"
  ]
}
