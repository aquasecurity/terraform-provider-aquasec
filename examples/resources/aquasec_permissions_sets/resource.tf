resource "aquasec_permissions_sets" "my_terraform_perm_set" {
    name = "my_terraform_perm_set"
    description     = "created from terraform"
    author    = "system"
    ui_access = true
    is_super = false
    actions = [
        "dashboard.read",
        "risks.vulnerabilities.read",
        "risks.vulnerabilities.write",
        "risks.host_images.read",
        "risks.benchmark.read",
        "risk_explorer.read",
        "images.read",
        "image_profiles.read",
        "image_assurance.read",
        "image_assurance.write",
        "runtime_policies.read",
        "runtime_policies.write",
        "functions.read",
        "gateways.read",
        "secrets.read",
        "audits.read",
        "containers.read",
        "enforcers.read",
        "infrastructure.read",
        "consoles.read",
        "settings.read",
        "network_policies.read",
        "acl_policies.read",
        "acl_policies.write",
        "services.read",
        "integrations.read",
        "registries_integrations.read",
        "web_hook.read",
        "incidents.read"
    ]
}
