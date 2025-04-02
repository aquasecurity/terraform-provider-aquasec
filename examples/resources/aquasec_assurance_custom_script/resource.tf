resource "aquasec_assurance_custom_script" "aquasec_assurance_custom_script" {
	name        = "aquasec_assurance_custom_script"
	description = "Test assurance script"
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