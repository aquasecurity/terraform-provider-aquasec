data "aquasec_gateways" "testgateway" {}

output "gateway_data" {
  value = data.aquasec_gateways.testgateway
}

output "gateway_name" {
  value = data.aquasec_gateways.testgateway.gateways[0].id
}
output "gateway_status" {
  value = data.aquasec_gateways.testgateway.gateways[0].status
}
output "gateway_description" {
  value = data.aquasec_gateways.testgateway.gateways[0].description
}

output "gateway_version" {
  value = data.aquasec_gateways.testgateway.gateways[0].version
}

output "gateway_hostname" {
  value = data.aquasec_gateways.testgateway.gateways[0].hostname
}
output "gateway_grpc_address" {
  value = data.aquasec_gateways.testgateway.gateways[0].grpc_address
}