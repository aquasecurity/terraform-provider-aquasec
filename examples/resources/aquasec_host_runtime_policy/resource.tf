resource "aquasec_host_runtime_policy" "host_runtime_policy" {
  name = "host_runtime_policy"
  description = "host_runtime_policy"
  scope_variables {
    attribute = "kubernetes.cluster"
    value = "default"
  }
  scope_variables {
      attribute = "kubernetes.label"
      name = "app"
      value = "aqua"
  }

  application_scopes = [
    "Global",
  ]
  enabled = true
  enforce = false
  block_cryptocurrency_mining = true
  audit_brute_force_login = true
  enable_ip_reputation_security = true
  blocked_files = [
    "blocked",
  ]
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
  audit_all_os_user_activity    = true
  audit_full_command_arguments  = true
  audit_host_successful_login_events = true
  audit_host_failed_login_events = true
  audit_user_account_management = true
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
  package_block = [
    "package1"
  ]
  port_scanning_detection = true
  monitor_system_time_changes = true
  monitor_windows_services    = true
  monitor_system_log_integrity = true
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
}