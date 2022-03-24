data "aquasec_users" "users" {}

output "first_user_email" {
  value = data.aquasec_users_saas.users.users[0].email
}