terraform {
  required_providers {
    aquasec = {
      //      version = "0.8.7"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
  username = "admin"
  aqua_url = "https://aquaurl.com"
  password = "@password"
}


resource "aquasec_user" "name" {
  user_id  = "terraform-user"
  password = "password"
  name     = "Terraform User"
  email    = "terraform@test.com"
  roles = [
    "Scanner",
    "Administrator"
  ]
}

resource "aquasec_integration_registry" "demoregistry" {
  name = "terraform-ecr"
  url = "us-east-1"
  type = "AWS"
  username = "APIKEY"
  password = "SECRETKEY"
  prefixes = [
    "111111111111.dkr.ecr.us-east-1.amazonaws.com"
  ]
  auto_pull = true
}
resource "aquasec_firewall_policy" "test-policy" {
  name = "test-firewall-policy"
  description = "this is a test firewall policy"

  block_icmp_ping = true
  block_metadata_service = false

  inbound_networks {
    allow = true
    port_range = "8080-9999"
    resource_type = "anywhere"
  }

  outbound_networks {
    allow = false
    port_range = "6060-7070"
    resource_type = "anywhere"
  }
}

resource "aquasec_service" "test-svc" {
  name = "test-svc"
  description = "test svc description"
  policies = [
    "default",
  ]

  priority = 95
  target = "container"

  scope_expression = "v1 || v2"
  scope_variables {
    attribute = "kubernetes.cluster"
    value = "default"
  }
  scope_variables {
      attribute = "kubernetes.cluster"
      value = "kube-system"
  }

  application_scopes = [
    "Global",
  ]
  enforce = true
}
resource "aquasec_enforcer_groups" "new" {
  group_id = "terraform"
  description = "Created1"
  logical_name = "terraform-eg"
  enforce = true
  gateways = [
    "local-cluster"
  ]
  type = "agent"
  orchestrator {
    type = "kubernetes"
    service_account = "aquasa"
    namespace = "aqua"
    master = false
  }
}
resource "aquasec_image" "test" {
  registry = "Docker Hub"
  repository = "elasticsearch"
  tag = "7.10.1"
}

resource "aquasec_notification_slack" "new" {
  name = "Slack"
  enabled = true
  type = "slack"
  channel = "#general"
  webhook_url = "https://hooks.slack.com/services/T01PHXXXXXX/XXXXXXABJSC/EnwXXXXXXeoVS3BhR9SkBDAo"
  user_name = "Aquasec"
}

resource "aquasec_container_runtime_policy" "test" {
  name                          = "test"
  description                   = "This is a container runtime policy"
  enforce                       = true
  enforce_after_days            = 9
  block_non_compliant_images    = true
  block_non_compliant_workloads = true
  block_container_exec          = true
  block_unregistered_images     = true
  enable_drift_prevention       = true
  allowed_executables = [
    "test",
    "exe",
  ]
  blocked_executables = [
    "test1",
    "exe1",
  ]

  blocked_files = [
    "test",
    "files",
  ]
  audit_all_processes_activity = true
  audit_full_command_arguments = true
  audit_all_network_activity   = true

  enable_fork_guard        = true
  fork_guard_process_limit = 12

  enable_ip_reputation_security = true

  blocked_packages = [
    "pkg",
  ]
  blocked_inbound_ports = [
    "80",
    "8080"
  ]
  blocked_outbound_ports = [
    "90",
    "9090"
  ]
  enable_port_scan_detection = true
  blocked_volumes = [
    "blocked",
    "vol"
  ]
  readonly_files_and_directories = [
    "readonly",
    "/dir/"
  ]
  exceptional_readonly_files_and_directories = [
    "readonly2",
    "/dir2/"
  ]
  block_access_host_network   = true
  block_adding_capabilities   = true
  block_use_pid_namespace     = true
  block_use_ipc_namespace     = true
  block_use_user_namespace    = true
  block_use_uts_namespace     = true
  block_privileged_containers = true
  block_root_user             = true
  block_low_port_binding      = true
  limit_new_privileges = true
  blocked_capabilities = [
    "ALL"
  ]
}

resource "aquasec_function_runtime_policy" "test" {
  name                          = "test-function-terraform"
  description                   = "This is a test description."
  enforce                       = true
  block_malicious_executables   = true

  blocked_executables = [
    "bin",
    "exe",
  ]
}

resource "aquasec_host_runtime_policy" "test" {
  name               = "test-host-terraform"
  description        = "This is a test host runtime policy."
  enabled            = true
  enforce            = false
  enforce_after_days = 4
  blocked_files = [
    "blocked",
  ]
  audit_all_os_user_activity    = true
  audit_full_command_arguments  = true
  enable_ip_reputation_security = true
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
  monitor_system_time_changes = true
  monitor_windows_services    = true

  windows_registry_monitoring {
    monitor_create      = true
    monitor_read        = true
    monitor_modify      = true
    monitor_delete      = true
    monitor_attributes  = true
    monitored_paths     = ["paths"]
    excluded_paths      = ["expaths"]
    monitored_processes = ["process"]
    excluded_processes  = ["exprocess"]
    monitored_users     = ["user"]
    excluded_users      = ["expuser"]
  }

  windows_registry_protection {
    protected_paths     = ["paths"]
    excluded_paths      = ["expaths"]
    protected_processes = ["process"]
    excluded_processes  = ["exprocess"]
    protected_users     = ["user"]
    excluded_users      = ["expuser"]
  }

  file_integrity_monitoring {
    monitor_create      = true
    monitor_read        = true
    monitor_modify      = true
    monitor_delete      = true
    monitor_attributes  = true
    monitored_paths     = ["paths"]
    excluded_paths      = ["expaths"]
    monitored_processes = ["process"]
    excluded_processes  = ["exprocess"]
    monitored_users     = ["user"]
    excluded_users      = ["expuser"]
  }
}

resource "aquasec_image_assurance_policy" "newiap" {
    name = "testprovider"
    description = "Created using Terraform"
    application_scopes = [
        "Global"
    ]
    audit_on_failure = true
    fail_cicd = true
    block_failed = true
    whitelisted_licenses_enabled = true
    whitelisted_licenses = [
        "AGPL-3.0",
        "Apache-2.0",
        "BSD-2-Clause"
    ]
}

resource "aquasec_host_assurance_policy" "newhap" {
    name = "testprovider"
    description = "Created using Terraform"
    application_scopes = [
        "Global"
    ]
    audit_on_failure = true
    fail_cicd = true
    block_failed = true
    whitelisted_licenses_enabled = true
    whitelisted_licenses = [
        "AGPL-3.0",
        "Apache-2.0",
        "BSD-2-Clause"
    ]
}

resource "aquasec_function_assurance_policy" "newfap" {
    name = "testprovider"
    description = "Created using Terraform"
    application_scopes = [
        "Global"
    ]
    audit_on_failure = true
    fail_cicd = true
    block_failed = true
    maximum_score         = "1.0"
    maximum_score_enabled = true
}
