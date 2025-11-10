data "aquasec_monitoring_systems" "prom_mon" {}

output "prom_mon_name" {
  value = data.aquasec_monitoring_systems.prom_mon.monitors[0].name
}

output "prom_mon_interval" {
  value = data.aquasec_monitoring_systems.prom_mon.monitors[0].interval
}