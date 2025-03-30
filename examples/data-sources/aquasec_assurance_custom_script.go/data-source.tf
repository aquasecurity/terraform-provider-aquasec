data "aquasec_assurance_custom_script" "assurance_custom_script" {
	name = aquasec_assurance_custom_script.assurance_custom_script.id
}

output "aquasec_assurance_custom_script" {
  value = data.aquasec_assurance_custom_script.assurance_custom_script.snippet
}