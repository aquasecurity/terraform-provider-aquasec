resource "aquasec_permissions_sets" "my_terraform_perm_set" {
    name        = "my_terraform_perm_set"
    description = "Test Permissions Sets created by Terraform"
    ui_access   = true
    is_super    = false
    actions = [
        #################
    # Policies
    #################
    # Assurance Policies
    "acl_policies.read",                # Removed from version 2022.4
    "acl_policies.write",               # Removed from version 2022.4
    # Image Profiles
    "image_profiles.read",
    "image_profiles.write",             # Only for version 2022.4
    # Firewall Policies
    "network_policies.read",
    "network_policies.write",           # Only for version 2022.4
    # Runtime Policies
    "runtime_policies.read",
    "runtime_policies.write",
    # Response Policies                 # Only for version 2022.4
    "response_policies.read",           # Only for version 2022.4
    "response_policies.write",          # Only for version 2022.4
    # User Access Control Policies
    "image_assurance.read",
    "image_assurance.write",

    #################
    # Assets
    #################
    # Dashboard
    "dashboard.read",
    "dashboard.write",                  # Only for version 2022.4
    # Risk Explorer
    "risk_explorer.read",
    # Images
    "images.read",
    "images.write",                     # Only for version 2022.4
    # Host Images
    "risks.host_images.read",
    "risks.host_images.write",          # Only for version 2022.4
    # Functions
    "functions.read",
    "functions.write",                  # Only for version 2022.4
    # Enforcers
    "enforcers.read",
    "enforcers.write",                  # Only for version 2022.4
    # Containers
    "containers.read",
    # Services
    "services.read",
    "services.write",                   # Only for version 2022.4
    # Infrastructure
    "infrastructure.read",
    "infrastructure.write",             # Only for version 2022.4

    #################
    # Compliance
    #################
    # Vulnerabilities
    "risks.vulnerabilities.read",
    "risks.vulnerabilities.write",
    # CIS Benchmarks
    "risks.benchmark.read",
    "risks.benchmark.write",            # Only for version 2022.4

    #################
    # System
    #################
    # Audit Events
    "audits.read",
    # Secrets
    "secrets.read",
    "secrets.write",                    # Only for version 2022.4
    # Settings
    "settings.read",
    "settings.write",                   # Only for version 2022.4
    # Integrations
    "integrations.read",
    "integrations.write",               # Only for version 2022.4
    # Image Registry Integrations
    "registries_integrations.read",
    "registries_integrations.write",    # Only for version 2022.4
    # Scanner CLI                       # Only for version 2022.4
    "scan.read",                        # Only for version 2022.4
    # Gateways
    "gateways.read",
    "gateways.write",                   # Only for version 2022.4
    # Consoles
    "consoles.read",
    # Webhook authorization API
    "web_hook.read",
    # Incidents
    "incidents.read"
    ]
}
