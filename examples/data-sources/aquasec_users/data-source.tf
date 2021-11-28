data "aquasec_users" "users" {}

output "first_user_name" {
  value = data.aquasec_users.users.users[0].name // output: first_user_name = "administrator"
}