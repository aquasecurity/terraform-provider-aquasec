terraform {
  required_providers {
    aquasec = {
      source  = "aquasecurity/aquasec"
      version = "0.13.0"
    }
  }
}

provider "aquasec" {
  username = var.aquasec_username
  password = var.aquasec_password
  aqua_url = var.aquasec_url
}

#Resource blocks
resource "aquasec_acknowledge" "acknowledge" {
  comment = "comment"
  issues {
    docker_id        = ""
    image_name       = "image:latest"
    issue_name       = "CVE-2022-1271"
    issue_type       = "vulnerability"
    registry_name    = "registry"
    resource_cpe     = "cpe:/a:gnu:gzip:1.10"
    resource_name    = "gzip"
    resource_path    = "/usr/bin/gzip"
    resource_type    = "executable"
    resource_version = "1.10"
  }
}

resource "aquasec_application_scope_saas" "terraformiap" {
  description = "aquasec application scope saas"
  name        = "aquasec_application_scope_saas"
  // Categories is a nested block of artifacts, workloads and infrastructure
  categories {
    // Artifacts is a nested block of Image, Function, CF
    artifacts {
      // Every object requires expression(logical combinations of variables v1, v2, v3...) and list of variables consists of attribute(pre-defined) and value
      image {
        expression = "v1 && v2"
        variables {
          attribute = "aqua.registry"
          value     = "test-registry"
        }
        variables {
          attribute = "image.repo"
          value     = "nginx"
        }
      }
    }
    // Workloads is a nested block of Kubernetes, OS, CF
    workloads {
      // Every object requires expression(logical combinations of variables v1, v2, v3...) and list of variables consists of attribute(pre-defined) and value
      kubernetes {
        expression = "v1 && v2"
        variables {
          attribute = "kubernetes.cluster"
          value     = "aqua"
        }
        variables {
          attribute = "kubernetes.namespace"
          value     = "aqua"
        }
      }
    }
    // Infrastructure is a nested block of Kubernetes, OS
    infrastructure {
      // Every object requires expression and list of variables consists of attribute(pre-defined) and value
      kubernetes {
        expression = "v1"
        variables {
          attribute = "kubernetes.cluster"
          value     = "aqua"
        }
      }
    }
  }
}

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

resource "aquasec_aqua_label" "aqua_label" {
  name        = "example_label"
  description = "example_description"
}

resource "aquasec_assurance_custom_script" "aquasec_assurance_custom_script" {
  name        = "aquasec_assurance_custom_script"
  description = "Test assurance script"
  engine      = "yaml"
  path        = "test.yaml"
  kind        = "kubernetes"
  snippet     = <<-EOT
		---
		controls:
		version: "aks-1.1"
		id: 1
		text: "Control Plane Components"
		type: "master"
	EOT
}

resource "aquasec_container_runtime_policy" "container_runtime_policy" {
  name               = "full-container-runtime-policy-example"
  description        = "Comprehensive container runtime policy with all settings configured"
  runtime_type       = "container"
  runtime_mode       = 0
  enabled            = true
  enforce            = false
  enforce_after_days = 0
  is_ootb_policy     = false

  # Scope configuration
  scope {
    expression = "v1 || v2"

    variables {
      attribute = "kubernetes.namespace"
      value     = "production"
    }
    variables {
      attribute = "kubernetes.label"
      name      = "environment"
      value     = "production"
    }
  }

  # Container execution controls
  container_exec {
    enabled              = true
    block_container_exec = true
    container_exec_proc_white_list = [
      "/ecs-execute-command-*/amazon-ssm-agent",
      "/ecs-execute-command-*/ssm-session-worker",
      "/usr/bin/kubectl"
    ]
  }

  # Reverse shell protection
  reverse_shell {
    enabled                       = true
    block_reverse_shell           = true
    reverse_shell_ip_white_list   = ["10.0.0.1", "192.168.1.1"]
    reverse_shell_proc_white_list = ["/usr/bin/ssh", "/usr/bin/nc"]
  }

  # Drift prevention
  drift_prevention {
    enabled                  = true
    exec_lockdown            = true
    image_lockdown           = false
    exec_lockdown_white_list = ["/bin/bash", "/usr/bin/python", "/usr/local/bin/node"]
  }

  # Allowed executables
  allowed_executables {
    enabled                = true
    allow_executables      = ["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/git"]
    allow_root_executables = ["/sbin/iptables", "/sbin/modprobe", "/usr/sbin/nginx"]
  }

  # Allowed registries
  allowed_registries {
    enabled            = true
    allowed_registries = ["Docker Hub", "gcr.io", "quay.io", "registry.example.com"]
  }

  # Executable blacklist
  executable_blacklist {
    enabled     = true
    executables = ["nc", "ncat", "netcat", "telnet", "wget.exe"]
  }

  # Restricted volumes
  restricted_volumes {
    enabled = true
    volumes = [
      "/var/run/docker.sock",
      "/proc",
      "/sys",
      "/etc/kubernetes",
      "/var/lib/kubelet"
    ]
  }

  # Container privileges
  limit_container_privileges {
    enabled                  = true
    block_add_capabilities   = true
    prevent_root_user        = true
    privileged               = true
    ipcmode                  = true
    pidmode                  = true
    usermode                 = true
    utsmode                  = true
    prevent_low_port_binding = true
  }

  # Block settings
  block_fileless_exec           = true
  block_non_compliant_workloads = true
  block_non_k8s_containers      = true
  only_registered_images        = true
  block_disallowed_images       = true
  no_new_privileges             = true
  blocked_packages              = ["netcat", "telnet", "nmap", "wireshark", "tcpdump"]

  # Auditing
  auditing {
    enabled                       = true
    audit_all_processes           = true
    audit_process_cmdline         = true
    audit_all_network             = true
    audit_os_user_activity        = true
    audit_success_login           = true
    audit_failed_login            = true
    audit_user_account_management = true
  }

  # OS users controls
  blacklisted_os_users {
    enabled          = true
    user_black_list  = ["root", "admin", "administrator"]
    group_black_list = ["wheel", "sudo", "admin"]
  }

  whitelisted_os_users {
    enabled          = true
    user_white_list  = ["app", "service", "nonroot"]
    group_white_list = ["app", "service", "users"]
  }

  # File block
  file_block {
    enabled = true
    filename_block_list = [
      "/etc/shadow",
      "/etc/passwd",
      "/etc/ssh/sshd_config",
      "/etc/kubernetes/admin.conf"
    ]
    exceptional_block_files           = ["/var/log/*", "/tmp/*"]
    block_files_users                 = ["root", "admin"]
    block_files_processes             = ["/bin/cat", "/bin/less", "/bin/more"]
    exceptional_block_files_users     = ["app", "service"]
    exceptional_block_files_processes = ["/usr/bin/tail", "/usr/bin/grep"]
  }

  # File integrity monitoring
  file_integrity_monitoring {
    enabled                = true
    monitored_files_create = true
    monitored_files_modify = true
    monitored_files_delete = true
    monitored_files = [
      "/etc/*.conf",
      "/etc/*.config",
      "/etc/kubernetes/*.yaml",
      "/etc/passwd",
      "/etc/shadow"
    ]
    exceptional_monitored_files = [
      "/var/lib/docker/*",
      "/var/lib/kubelet/pods/*",
      "/tmp/*"
    ]
    monitored_files_processes             = ["/bin/bash", "/usr/bin/python", "/usr/bin/perl"]
    exceptional_monitored_files_processes = ["/usr/sbin/sshd", "/usr/bin/dockerd", "/usr/bin/kubelet"]
    monitored_files_users                 = ["root", "admin", "kubernetes"]
    exceptional_monitored_files_users     = ["app", "service", "nobody"]
  }

  # Package block
  package_block {
    enabled                              = true
    packages_black_list                  = ["netcat", "telnet", "nmap", "wireshark", "tcpdump"]
    exceptional_block_packages_files     = ["/usr/bin/ssh", "/usr/bin/scp"]
    block_packages_users                 = ["root", "admin"]
    block_packages_processes             = ["/bin/bash", "/bin/sh"]
    exceptional_block_packages_users     = ["app", "service"]
    exceptional_block_packages_processes = ["/usr/bin/python", "/usr/bin/perl"]
  }

  # Port block
  port_block {
    enabled              = true
    block_inbound_ports  = ["1-1024", "3306", "5432", "6379", "27017"]
    block_outbound_ports = ["1-1024", "3306", "5432", "6379", "27017"]
  }

  # Readonly files
  readonly_files {
    enabled = true
    readonly_files = [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/kubernetes/",
      "/etc/ssl/certs/"
    ]
    exceptional_readonly_files = [
      "/var/log/",
      "/tmp/"
    ]
    readonly_files_processes             = ["bash", "sh", "python"]
    exceptional_readonly_files_processes = ["sshd", "dockerd", "kubelet"]
    readonly_files_users                 = ["root", "admin"]
    exceptional_readonly_files_users     = ["app", "service"]
  }

  # Malware scan options
  malware_scan_options {
    enabled                  = true
    action                   = "alert"
    file_forensic_collection = true
    include_directories      = ["C:\\*", "/*"]
    exclude_directories      = ["/proc", "/sys", "/dev", "/tmp"]
    exclude_processes        = ["sshd", "dockerd", "kubelet"]
  }

  # System integrity protection
  system_integrity_protection {
    enabled                     = true
    audit_systemtime_change     = true
    windows_services_monitoring = true
    monitor_audit_log_integrity = true
  }

  # Failed Kubernetes checks
  failed_kubernetes_checks {
    enabled = true
    failed_checks = [
      "CVE-2021-25741",
      "CVE-2022-0185",
      "CVE-2022-24348",
      "CVE-2022-3172"
    ]
  }

  # Additional security features
  enable_fork_guard           = true
  enable_ip_reputation        = true
  enable_crypto_mining_dns    = true
  enable_port_scan_protection = true
  monitor_system_time_changes = true
}

resource "aquasec_enforcer_groups" "group" {
  group_id = "tf-test-enforcer"
  type     = "agent"
  enforce  = true
  # Host Assurance
  host_assurance = true
  # Network Firewall (Host Protection)
  host_network_protection = true
  # Runtime Controls
  host_protection = true
  # Network Firewall (Container Protection)
  network_protection = true
  # Advanced Malware Protection (Container Protection)
  container_antivirus_protection = true
  # Runtime Controls
  container_activity_protection = true
  # Image Assurance
  image_assurance = true
  # Advanced Malware Protection (Host Protection)
  antivirus_protection = true
  # Host Images
  sync_host_images = true
  # Risk Explorer
  risk_explorer_auto_discovery = true
  # host_forensics
  host_forensics_collection = true
  # forensics
  forensics = true

  orchestrator {}
}

resource "aquasec_enforcer_groups" "group-kube_enforcer" {
  group_id = "tf-test-kube_enforcer"
  type     = "kube_enforcer"
  enforce  = true

  # Enable admission control
  admission_control = true
  # Perform admission control if not connected to a gateway
  block_admission_control = true
  # Enable workload discovery
  auto_discovery_enabled = true
  # Register discovered pod images
  auto_scan_discovered_images_running_containers = true
  # Add discovered registries
  auto_discover_configure_registries = true
  # Kube-bench image path
  kube_bench_image_name = "registry.aquasec.com/kube-bench:v0.6.5"
  # Secret that holds the registry credentials for the Pod Enforcer and kube-bench
  micro_enforcer_secrets_name = "aqua-registry"
  # Auto copy these secrets to the Pod Enforcer namespace and container
  auto_copy_secrets = true

  orchestrator {
    type      = "kubernetes"
    namespace = "aqua"
  }
}

resource "aquasec_firewall_policy" "example_firewall_policy" {
  // Required values
  name = "example_firewall_policy"

  // Block ICMP and one inbound/outbound block
  block_icmp_ping = true
  inbound_networks {
    allow         = false
    resource_type = "anywhere"
    port_range    = "0-1000"
  }

  outbound_networks {
    allow         = false
    resource_type = "custom"
    port_range    = "0-1000"
    resource      = "192.168.1.5/32"
  }
}

resource "aquasec_function_assurance_policy" "example_function_assurance_policy" {
  //Required values
  application_scopes = ["Global"]
  name               = "example_function_assurance_policy"
  assurance_type     = "function"

  //Values that default to true
  audit_on_failure = true
  block_failed     = true
  fail_cicd        = true

  function_integrity_enabled    = true
  enforce_excessive_permissions = true
  scan_sensitive_data           = true
  cvss_severity                 = "critical"
  cvss_severity_enabled         = true

}

resource "aquasec_function_runtime_policy" "audit_mode_example" {
  # Basic configuration
  name        = "function-policy-audit-mode"
  description = "Function runtime policy in audit mode for serverless functions"
  version     = "1.0"

  # Scope configuration
  scope {
    expression = "v1"
    variables {
      attribute = "function.name"
      value     = "*"
    }
  }

  # Application scope
  application_scopes = ["Global"]

  # Set to Audit mode (not enforcing)
  enabled = true
  enforce = false

  # Optional: Automatically switch to enforce mode after a period
  enforce_after_days = 14

  # Honeypot configuration (simplified to just use tripwire block)
  # tripwire {
  #   enabled        = true
  #   user_id        = "example_access_key"
  #   user_password  = "example_secret_key"
  #   apply_on       = ["Function"]
  #   serverless_app = "my-serverless-app" # Must be a real app in your environment
  # }

  # Block malicious activity
  executable_blacklist {
    enabled     = true
    executables = ["nc", "netcat", "wget", "curl", "bash"]
  }

  # Drift prevention
  drift_prevention {
    enabled                  = true
    exec_lockdown            = true
    image_lockdown           = false
    exec_lockdown_white_list = ["authorized_process"]
  }

  # Malware scanning
  malware_scan_options {
    enabled             = true
    action              = "Alert"
    include_directories = ["/var/task", "/opt"]
    exclude_directories = ["/tmp", "/var/runtime"]
  }

  # File integrity monitoring
  file_integrity_monitoring {
    enabled                    = true
    monitored_files            = ["/etc/passwd", "/etc/shadow", "/var/task/index.js"]
    monitored_files_read       = true
    monitored_files_modify     = true
    monitored_files_attributes = true
    monitored_files_create     = true
    monitored_files_delete     = true
  }

  # Network security
  enable_crypto_mining_dns = false

  # Other security settings
  block_fileless_exec = false
}

resource "aquasec_group" "group" {
  name = "IacGroup"
}

resource "aquasec_host_assurance_policy" "advanced" {

  name               = "host_policy_advanced"
  description        = "Advanced host assurance policy with key security controls"
  application_scopes = ["Global"]
  assurance_type     = "host"

  # Policy enforcement
  enabled          = true
  audit_on_failure = true
  block_failed     = true


  # Vulnerability management
  cvss_severity_enabled     = true
  cvss_severity             = "critical"
  maximum_score_enabled     = true
  maximum_score             = 7
  vulnerability_score_range = [7, 10]

  # CIS compliance checks
  docker_cis_enabled = true
  kube_cis_enabled   = true
  linux_cis_enabled  = true

  # Malware scanning configuration
  disallow_malware = true
  malware_action   = "block"
  monitored_malware_paths = [
    "/tmp",
    "/var/tmp"
  ]

  # Auto scanning configuration
  auto_scan_enabled    = true
  auto_scan_configured = true
  auto_scan_time {
    iteration_type = "daily"
    time           = "2024-01-01T00:00:00Z"
  }

  # Basic policy settings
  policy_settings {
    enforce         = true
    warn            = true
    warning_message = "Host failed security compliance checks"
  }
}

resource "aquasec_host_runtime_policy" "host_runtime_policy" {
  name        = "host_runtime_policy"
  description = "host_runtime_policy"

  scope {
    expression = "v1 && v2 || v3"

    variables {
      attribute = "aqua.hostgroup"
      value     = "production"
    }
    variables {
      attribute = "cloud.awsaccount"
      value     = "xxxxxxxxx"
    }
    variables {
      attribute = "os.hostname"
      name      = "name"
      value     = "10.0.0.1"
    }
  }


  application_scopes = [
    "Global",
  ]
  enabled                     = true
  enforce                     = false
  block_cryptocurrency_mining = true
  audit_brute_force_login     = true
  blocked_files = [
    "blocked",
  ]
  file_integrity_monitoring {
    enabled                               = true
    monitored_files_read                  = true
    monitored_files_modify                = true
    monitored_files_delete                = true
    monitored_files_attributes            = false
    monitored_files                       = ["paths"]
    exceptional_monitored_files           = ["expaths"]
    monitored_files_processes             = ["process"]
    exceptional_monitored_files_processes = ["exprocess"]
    monitored_files_users                 = ["user"]
    exceptional_monitored_files_users     = ["expuser"]
  }

  audit_full_command_arguments       = true
  audit_host_successful_login_events = true
  audit_host_failed_login_events     = true
  audit_user_account_management      = true
  os_users_allowed = [
    "user1",
  ]
  os_groups_allowed = [
    "group1",
  ]
  os_users_blocked = [
    "user2",
  ]
  os_groups_blocked = [
    "group2",
  ]

  monitor_system_time_changes  = true
  monitor_windows_services     = true
  monitor_system_log_integrity = true
}

resource "aquasec_image" "example_aquasec_image" {
  registry   = "ExampleRegistry"
  repository = "ExampleRepository"
  tag        = "ExampleImageTag"
}

resource "aquasec_image_assurance_policy" "test_image_policy" {
  name               = "test_image_assurance_policy"
  application_scopes = ["Global"]
  assurance_type     = "image"

  block_failed     = true
  fail_cicd        = true
  audit_on_failure = true

  cvss_severity         = "critical"
  cvss_severity_enabled = true
  disallow_malware      = true
  scan_sensitive_data   = true

}

resource "aquasec_integration_registry" "integration_registry" {
  name                           = "integration_registry"
  type                           = "AWS"
  advanced_settings_cleanup      = false
  always_pull_patterns           = [":latest", ":v1"]
  author                         = "aqua@aquasec.com"
  auto_cleanup                   = false
  auto_pull                      = true
  auto_pull_interval             = 1
  auto_pull_max                  = 100
  auto_pull_rescan               = false
  auto_pull_time                 = "08:45"
  description                    = "Automatically discovered registry"
  image_creation_date_condition  = "image_count"
  permission                     = "GlobalPermission"
  nexus_mtts_ff_enabled          = true
  auto_pull_latest_xff_enabled   = true
  is_architecture_system_default = false

  options {
    option = "ARNRole"
    value  = "arn:aws:iam::111111111111:role/terraform"
  }
  options {
    option = "sts:ExternalId"
    value  = "test1-test2-test3"
  }
  options {
    option = "TestImagePull"
    value  = "nginx:latest"
  }

  prefixes = [
    "111111111111.dkr.ecr.us-east-1.amazonaws.com"
  ]

  pull_image_age              = "0D"
  pull_image_count            = 3
  pull_image_tag_pattern      = [":Latest", ":latest"]
  pull_repo_patterns_excluded = [":xyz", ":onlytest"]
  pull_repo_patterns          = [""]
  pull_tags_pattern           = [""]
  pull_max_tags               = 1

  url                = "us-east-1"
  scanner_name       = []
  scanner_type       = "any"
  scanner_group_name = "terraform-test" //configure when scanner_type is "specific"

  username    = ""
  password    = ""
  client_cert = ""
  client_key  = ""
  webhook {
    enabled       = true
    url           = "https://aquasec.com/"
    auth_token    = "test1-test2-test3"
    un_quarantine = false
  }
  auto_scan_time {
    auto_pull_day  = 1
    iteration      = 1
    iteration_type = "week"                                                   // "none", "day", "week", "month"
    time           = "2025-07-09T08:45:00Z"                                   //YYYY-MM-DDTHH:MM:SSZ
    week_days      = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"] // ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
  }

  force_ootb = false
  force_save = false
}

resource "aquasec_kubernetes_assurance_policy" "example_kubernetes_assurance_policy" {
  // Values that are required
  application_scopes = ["Global"]
  name               = "example_kubernetes_assurance_policy"
  assurance_type     = "kubernetes"

  //Values that default to true
  audit_on_failure = true
  block_failed     = true

  kubernetes_controls {
    avd_id      = "AVD-KSV-0121"
    description = "HostPath present many security risks and as a security practice it is better to avoid critical host paths mounts."
    enabled     = true
    kind        = "workload"
    name        = "Kubernetes resource with disallowed volumes mounted"
    ootb        = true
    script_id   = 104
    severity    = "high"
  }
}



resource "aquasec_notification" "slack" {
  name       = "slack-example"
  type       = "slack"
  properties = {}
}

resource "aquasec_notification_slack" "example" {
  channel     = "test-channel"
  enabled     = true
  type        = "slack"
  user_name   = ""
  webhook_url = ""

  # Optional fields
  icon        = "https://example.com/icon.png"
  main_text   = "AquaSec alert notification"
  name        = "slack-alert"
  service_key = ""
}

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

resource "aquasec_role" "IaC" {
  role_name   = "RoleIaC"
  description = "RoleIaC"
  permission  = "PermissionIaC"
  scopes      = ["Global"]
}

resource "aquasec_role_mapping" "role_mapping" {
  saml {
    role_mapping = {
      Administrator = "group1"
      Scanner       = "group2|group3"
    }
  }
}

resource "aquasec_role" "example" {
  role_name   = "ExampleTeam"
  description = "Role for ExampleTeam with limited access"
  permission  = aquasec_permission_set_saas.example.name
  scopes      = ["Global"]
}

resource "aquasec_role_mapping_saas" "example" {
  saml_groups = ["Engineering", "Security"]
  csp_role    = aquasec_role.example.role_name
}

resource "aquasec_scanner_group" "example" {
  name               = "terraformTest"
  type               = "remote"
  os_type            = "linux"
  description        = "for testing purpose"
  application_scopes = ["Global"]
  registries = [
    "TerraformTest",
  ]
}

resource "aquasec_service" "example_service" {
  name               = "svc_example"
  description        = "Example service with global and local policies"
  target             = "container"
  priority           = 90
  application_scopes = ["Global"]
  enforce            = true

  policies = ["default", "policy1", "policy2"]

  local_policies {
    name        = "policy1"
    type        = "access.control"
    description = "Local policy 1 for inbound and outbound control"

    inbound_networks {
      port_range    = "22/22"
      resource_type = "anywhere"
      allow         = true
    }

    outbound_networks {
      port_range    = "80/80"
      resource_type = "anywhere"
      allow         = true
    }

    block_metadata_service = false
  }

  local_policies {
    name        = "policy2"
    type        = "access.control"
    description = "Local policy 2 with stricter outbound control"

    inbound_networks {
      port_range    = "443/443"
      resource_type = "custom"
      resource      = "190.1.2.3/12"
      allow         = true
    }

    outbound_networks {
      port_range    = "8080/8080"
      resource_type = "custom"
      resource      = "190.1.2.3/12"
      allow         = false
    }

    block_metadata_service = true
  }
}

resource "aquasec_user" "IaC" {
  user_id  = "IaC"
  password = var.aquasec_password
  roles = [
    "infrastructure"
  ]

  email      = "infrastructure@example.com"
  first_time = true
  name       = "Infrastructure as Code"
}

resource "aquasec_user_saas" "IaC2" {
  email = "infrastructure2@example.com"
  csp_roles = [
    "Default"
  ]
  account_admin = false
  mfa_enabled   = false
  //optional
  groups {
    name = "IacGroupName"
  }
}

resource "aquasec_vmware_assurance_policy" "example_vmware_assurance_policy" {
  application_scopes = ["Global"]
  name               = "example_vmware_assurance_policy"
  assurance_type     = "cf_application"

  audit_on_failure = true
  block_failed     = true
  fail_cicd        = true

  scan_sensitive_data   = true
  cvss_severity_enabled = true
  cvss_severity         = "critical"
}

resource "aquasec_log_management" "log_management_cloudwatch" {
  name         = "CloudWatch"
  region       = var.aws_region
  loggroup     = var.aws_log_group
  key          = var.aws_secret_key
  keyid        = var.aws_access_key
  enable       = true
  audit_filter = ""
}

#resource "aquasec_serverless_application" "serverless_application" {
#  name               = "tf-test-sls"
#  region             = "us-west-1"
#  compute_provider   = 3 # 1 - AWS Lambda, 3 - Azure Function, 5 - Google Cloud Functions
#  username           = var.azure_username
#  password           = var.azure_password
#  tenant_id          = var.azure_tenant_id
#  subscription_id    = var.azure_subscription_id
#  scanner_type       = "any"
#  scanner_group_name = "test-remote-scanner"
#  description        = "Serverless Application terraform provider"
#  auto_pull          = true
#  auto_pull_time     = "03:00"
#}

resource "aquasec_monitoring_system" "prometheus_monitoring" {
  name     = "Prometheus"
  enabled  = true
  interval = 1
  type     = "prometheus"
  token    = ""
}

#Data sources block
data "aquasec_acknowledges" "acknowledges" {}

output "acknowledges" {
  value = data.aquasec_acknowledges.acknowledges
}

data "aquasec_application_scope" "default" {
  name = "Global"
}

output "application_scopes" {
  value = data.aquasec_application_scope.default
}

output "codebuild_config" {
  value = try(
    tolist([
      for category in data.aquasec_application_scope.default.categories : [
        for artifact in(category.artifacts != null ? category.artifacts : []) : artifact.codebuild
        if artifact.codebuild != null
      ]
    ])[0][0],
    null
  )
}

data "aquasec_application_scope_saas" "saas" {
  name = "Global"
}

output "application_scope_saas" {
  value = data.aquasec_application_scope_saas.saas
}

output "name" {
  value = data.aquasec_application_scope_saas.saas.name
}

output "categories" {
  value = data.aquasec_application_scope_saas.saas.categories
}

data "aquasec_aqua_api_keys" "single" {
  id = aquasec_aqua_api_key.terraform_api_key.id
}

output "api_key_single_id" {
  value = data.aquasec_aqua_api_keys.single.apikeys[0].id
}
output "group_id" {
  value = data.aquasec_aqua_api_keys.single.apikeys[0].group_id
}
output "expiration" {
  value = data.aquasec_aqua_api_keys.single.apikeys[0].expiration
}
output "permission_ids" {
  value = data.aquasec_aqua_api_keys.single.apikeys[0].permission_ids
}
output "roles" {
  value = data.aquasec_aqua_api_keys.single.apikeys[0].roles
}

output "secret" {
  value     = aquasec_aqua_api_key.terraform_api_key.secret
  sensitive = true
}

data "aquasec_aqua_api_keys" "list" {
  limit  = 10
  offset = 0
}

output "api_key_list" {
  value     = data.aquasec_aqua_api_keys.list
  sensitive = true
}

data "aquasec_aqua_labels" "aqua_labels" {}

output "aqua_labels_scope" {
  value = data.aquasec_aqua_labels.aqua_labels
}

data "aquasec_assurance_custom_script" "example" {
  script_id = "ID of the custom script"
}

output "assurance_custom_script_name" {
  value = data.aquasec_assurance_custom_script.example.name
}

data "aquasec_gateways" "testgateway" {}

output "gateway_data" {
  value = data.aquasec_gateways.testgateway
}

output "gateway_name" {
  value = data.aquasec_gateways.testgateway.gateways[0].id
}
output "gateway_status" {
  value = data.aquasec_gateways.testgateway.gateways[0].status
}
output "gateway_description" {
  value = data.aquasec_gateways.testgateway.gateways[0].description
}

output "gateway_version" {
  value = data.aquasec_gateways.testgateway.gateways[0].version
}

output "gateway_hostname" {
  value = data.aquasec_gateways.testgateway.gateways[0].hostname
}
output "gateway_grpc_address" {
  value = data.aquasec_gateways.testgateway.gateways[0].grpc_address
}

data "aquasec_groups" "groups" {}

output "first_group_name" {
  value = data.aquasec_groups.groups.groups.0.name
}

data "aquasec_image" "test" {
  registry   = "Docker Hub"
  repository = "alpine"
  tag        = "3.19"
}

output "image" {
  value = data.aquasec_image.test
}

data "aquasec_notifications" "slack-example" {}

output "slack-notification" {
  value = data.aquasec_notifications.slack-example
}

data "aquasec_permissions_sets" "testpermissionsset" {}

output "permissions_sets" {
  value = data.aquasec_permissions_sets.testpermissionsset
}

output "permissions_sets_names" {
  value = data.aquasec_permissions_sets.testpermissionsset[*].permissions_sets[*].name
}

data "aquasec_permissions_sets_saas" "example" {}

output "permissions_sets_saas" {
  value = data.aquasec_permissions_sets_saas.example
}

output "permissions_sets_names_saas" {
  value = data.aquasec_permissions_sets_saas.example[*].permissions_sets[*].name
}

output "dashboard_permissions" {
  value = [
    for ps in data.aquasec_permissions_sets_saas.example.permissions_sets : ps.name
    if contains(ps.actions, "cnapp.dashboards.read")
  ]
}

data "aquasec_roles" "roles" {}

output "role_first_user_name" {
  value = data.aquasec_roles.roles.roles[0]
}

data "aquasec_roles_mapping_saas" "roles_mapping_saas" {}

output "role_mapping" {
  value = data.aquasec_roles_mapping_saas.roles_mapping_saas.roles_mapping
}

data "aquasec_scanner_group" "all" {}

output "scanner_group_names" {
  value = [for sg in data.aquasec_scanner_group.all.scanner_groups : sg.name]
}

data "aquasec_permissions_sets_saas" "saas" {}

output "data_permissions_sets_saas" {
  value = data.aquasec_permissions_sets_saas.saas
}

output "data_permissions_sets_names_saas" {
  value = data.aquasec_permissions_sets_saas.saas[*].permissions_sets[*].name
}

output "data_dashboard_permissions_saas" {
  value = [
    for ps in data.aquasec_permissions_sets_saas.saas.permissions_sets : ps.name
    if contains(ps.actions, "cnapp.dashboards.read")
  ]
}

#data "aquasec_log_managements" "log_managements" {}

#output "log_managements" {
#  value = data.aquasec_log_managements.log_managements
#}

data "aquasec_monitoring_systems" "prom_mon" {}

output "prom_mon_name" {
  value = data.aquasec_monitoring_systems.prom_mon.monitors[0].name
}

output "prom_mon_interval" {
  value = length(data.aquasec_monitoring_systems.prom_mon.monitors) > 0 ? data.aquasec_monitoring_systems.prom_mon.monitors[0].interval : null
}