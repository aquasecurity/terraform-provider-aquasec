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
