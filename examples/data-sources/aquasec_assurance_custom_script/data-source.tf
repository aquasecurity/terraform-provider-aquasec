resource "aquasec_assurance_custom_script" "example" {
	name        = "example"
	description = "example assurance script"
	engine      = "yaml"
	path        = "test.yaml"
	kind        = "kubernetes"
	snippet     = <<-EOT
		---
		controls:
		version: "aks-1.1"
		id: 1
		text: "Control Plane Components"
		type: "master"
	EOT
}

data "aquasec_assurance_custom_script" "example" {
	name = aquasec_assurance_custom_script.example.id
}

output "name" {
  value = data.aquasec_assurance_custom_script.example.name
}