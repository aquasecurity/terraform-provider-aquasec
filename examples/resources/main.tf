terraform {
  required_providers {
    aquasec = {
      //version = "0.8.37"
      source = "aquasecurity/aquasec"
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
  name     = "terraform-ecr"
  url      = "us-east-1"
  type     = "AWS"
  username = "APIKEY"
  password = "SECRETKEY"
  prefixes = [
    "111111111111.dkr.ecr.us-east-1.amazonaws.com"
  ]
  auto_pull = true
}
resource "aquasec_firewall_policy" "test-policy" {
  name        = "test-firewall-policy"
  description = "this is a test firewall policy"

  block_icmp_ping        = true
  block_metadata_service = false

  inbound_networks {
    allow         = true
    port_range    = "8080-9999"
    resource_type = "anywhere"
  }

  outbound_networks {
    allow         = false
    port_range    = "6060-7070"
    resource_type = "anywhere"
  }
}

resource "aquasec_service" "test-svc" {
  name        = "test-svc"
  description = "test svc description"
  policies = [
    "default",
  ]

  priority = 95
  target   = "container"

  scope_expression = "v1 || v2"
  scope_variables {
    attribute = "kubernetes.cluster"
    value     = "default"
  }
  scope_variables {
    attribute = "kubernetes.cluster"
    value     = "kube-system"
  }

  application_scopes = [
    "Global",
  ]
  enforce = true
}
resource "aquasec_enforcer_groups" "new" {
  group_id     = "terraform"
  description  = "Created1"
  logical_name = "terraform-eg"
  enforce      = true
  gateways = [
    "local-cluster"
  ]
  type = "agent"
  orchestrator {
    type            = "kubernetes"
    service_account = "aquasa"
    namespace       = "aqua"
    master          = false
  }
}
resource "aquasec_image" "test" {
  registry   = "Docker Hub"
  repository = "elasticsearch"
  tag        = "7.10.1"
}

resource "aquasec_notification_slack" "new" {
  name        = "Slack"
  enabled     = true
  type        = "slack"
  channel     = "#general"
  webhook_url = "https://hooks.slack.com/services/T01PHXXXXXX/XXXXXXABJSC/EnwXXXXXXeoVS3BhR9SkBDAo"
  user_name   = "Aquasec"
}

resource "aquasec_container_runtime_policy" "test" {
  name                          = "test"
  description                   = "This is a container runtime policy"
  enforce                       = true
  enforce_after_days            = 9
  block_non_compliant_workloads = true
  block_container_exec          = true
  allowed_executables {
    enabled = true
    allow_executables = [
      "pkg",
      "txt"
    ]
  }
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


  malware_scan_options {
    enabled = true
    action  = "alert"
    #exclude_directories = [ "/var/run/" ]
  }
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
  blocked_volumes = [
    "blocked",
    "vol"
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
  limit_new_privileges        = true
  blocked_capabilities = [
    "ALL"
  ]
}

resource "aquasec_function_runtime_policy" "test" {
  name        = "test-function-terraform"
  description = "This is a test description."
  enforce     = true
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
  audit_full_command_arguments = true
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

  file_integrity_monitoring {
    monitored_files_create                = true
    monitored_files_read                  = true
    monitored_files_modify                = true
    monitored_files_delete                = true
    monitored_files_attributes            = true
    monitored_files                       = ["paths"]
    exceptional_monitored_files           = ["expaths"]
    monitored_files_processes             = ["process"]
    exceptional_monitored_files_processes = ["exprocess"]
    monitored_files_users                 = ["user"]
    exceptional_monitored_files_users     = ["expuser"]
  }
}

resource "aquasec_image_assurance_policy" "newiap" {
  name           = "testprovider"
  assurance_type = "image"
  description    = "Created using Terraform"
  application_scopes = [
    "Global"
  ]
  audit_on_failure             = true
  fail_cicd                    = true
  block_failed                 = true
  whitelisted_licenses_enabled = true
  whitelisted_licenses = [
    "AGPL-3.0",
    "Apache-2.0",
    "BSD-2-Clause"
  ]
}

resource "aquasec_permissions_sets" "my_terraform_perm_set" {
  name        = "my_terraform_perm_set"
  description = "created from terraform"
  author      = "system"
  ui_access   = true
  is_super    = false
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
resource "aquasec_host_assurance_policy" "newhap" {
  name        = "testprovider"
  description = "Created using Terraform"
  application_scopes = [
    "Global"
  ]
  audit_on_failure             = true
  fail_cicd                    = true
  block_failed                 = true
  whitelisted_licenses_enabled = true
  whitelisted_licenses = [
    "AGPL-3.0",
    "Apache-2.0",
    "BSD-2-Clause"
  ]
}

resource "aquasec_function_assurance_policy" "newfap" {
  name        = "testprovider"
  description = "Created using Terraform"
  application_scopes = [
    "Global"
  ]
  audit_on_failure      = true
  fail_cicd             = true
  block_failed          = true
  maximum_score         = "1.0"
  maximum_score_enabled = true
}

resource "aquasec_application_scope" "terraformiap" {
  description = "test123"
  name        = "test18"
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