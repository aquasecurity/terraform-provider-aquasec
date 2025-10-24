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

variable "aws_access_key" {
  description = "AWS Access Key"
  type        = string
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  type        = string
  sensitive   = true
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
}

variable "aws_log_group" {
  description = "AWS Log Group"
  type        = string
}
variable "log_management_name" {
  description = "Log Management Name"
  type        = string
}

variable "enable_log_management" {
  description = "Enable Log Management"
  type        = bool
  default     = true
}