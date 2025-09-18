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
    enabled = true
    action  = "alert"
    //file_forensic_collection = true
    include_directories = ["C:\\*", "/*"]
    exclude_directories = ["/proc", "/sys", "/dev", "/tmp"]
    exclude_processes   = ["sshd", "dockerd", "kubelet"]
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
