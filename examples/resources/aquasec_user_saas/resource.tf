resource "aquasec_user_saas" "IaC1" {
    email    = "infrastructure1@example.com"
    csp_roles = []
    account_admin = true
}

resource "aquasec_user_saas" "IaC2" {
    email    = "infrastructure2@example.com"
    csp_roles = [
        "Default"
    ]
    account_admin = false
    //optional
    groups {
        name = "IacGroupName"
        group_admin = false
    }
}