resource "aquasec_monitoring_system" "prometheus_monitoring" {
  name     = "Prometheus"
  enabled  = true
  interval = 1
  type     = "prometheus"
  token    = ""
}