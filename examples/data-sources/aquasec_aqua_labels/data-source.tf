data "aquasec_aqua_labels" "aqua_labels" {}

# Print all Aqua labels
output "scopes" {
  value = data.aquasec_aqua_labels.aqua_labels
}