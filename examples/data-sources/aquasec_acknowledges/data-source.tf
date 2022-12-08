data "aquasec_acknowledges" "acknowledges" {}

output "acknowledges" {
  value = data.aquasec_acknowledges.acknowledges
}
