variable "aquasec_username" {
  description = "Aqua Username"
  type        = string
  sensitive   = true
}

variable "aquasec_url" {
  description = "Aqua Console URL"
  type        = string
}

variable "aquasec_password" {
  description = "Aqua password"
  type        = string
  sensitive   = true
}