resource "aquasec_container_runtime_policy" "container_runtime_policy" {
  name = "container_runtime_policy"
  description = "container_runtime_policy"
  enabled = true
  enforce = false
  block_container_exec          = true
  container_exec_allowed_processes = [
    "proc1",
    "proc2"
  ]
  block_cryptocurrency_mining = true
  block_fileless_exec = true
  block_non_compliant_images    = true
  block_non_compliant_workloads = true
  block_non_k8s_containers = true
  block_reverse_shell = true
  reverse_shell_allowed_processes = [
    "proc1",
    "proc2"
  ]
  reverse_shell_allowed_ips = [
    "ip1",
    "ip2"
  ]
  block_unregistered_images     = true
  blocked_capabilities = [
    "AUDIT_CONTROL",
    "AUDIT_WRITE"
  ]
  enable_ip_reputation_security = true
  enable_drift_prevention       = true
  allowed_executables = [
    "exe",
    "bin",
  ]
  blocked_executables = [
    "exe1",
    "exe2",
  ]
  blocked_files = [
    "test1",
    "test2"
  ]
  malware_scan_options {
    enabled = true
    action = "alert"
    #exclude_directories = [ "/var/run/" ]
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
  audit_all_processes_activity  = true
  audit_full_command_arguments  = true
  audit_all_network_activity    = true
  enable_fork_guard             = true
  fork_guard_process_limit      = 13
  block_access_host_network     = true
  block_adding_capabilities     = true
  block_root_user               = true
  block_privileged_containers   = true
  block_use_ipc_namespace       = true
  block_use_pid_namespace       = true
  block_use_user_namespace      = true
  block_use_uts_namespace       = true
  block_low_port_binding        = true
  limit_new_privileges          = true
  blocked_packages = [
    "pkg",
    "pkg2"
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
  readonly_files_and_directories = [
    "readonly",
    "/dir/"
  ]
  exceptional_readonly_files_and_directories = [
    "readonly2",
    "/dir2/"
  ]
  allowed_registries = [
    "registry1",
    "registry2"
  ]
  monitor_system_time_changes = "true"
  blocked_volumes = [
    "blocked",
    "vol"
  ]
}