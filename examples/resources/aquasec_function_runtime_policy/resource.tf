# Example: Function Runtime Policy in Audit Mode 
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