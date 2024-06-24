resource "aquasec_kubernetes_assurance_policy" "example_kubernetes_assurance_policy" {
  // Values that are required
  application_scopes = ["Global"]
  name               = "example_kubernetes_assurance_policy"

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