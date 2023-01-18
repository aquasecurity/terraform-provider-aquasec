# Please note that when importing an email\ jira notification, the password will not be imported. However, when running the apply command, the password will be updated and applied to the resource

resource "aquasec_notification" "teams" {
    name = "team-example"
    type = "teams"
    properties = {
        url = "<TEAMS-URL>"
    }
}

resource "aquasec_notification" "slack" {
    name = "slack-example"
    type = "slack"
    properties = {
        url = "<SLACK-URL>"
    }
}

resource "aquasec_notification" "webhook" {
    name = "webhook-example"
    type = "webhook"
    properties = {
        url = "<WEBHOOK-URL>"
    }
}

resource "aquasec_notification" "servicenow" {
    name = "servicenow-example"
    type = "serviceNow"
    properties = {
        user = "<USERNAME>"
        password = "<PASSWORD>"
        url = "<SERVICENOW-URL>"
        instance_name = ""
        #    board name (Table) - Optional
        board_name = ""
    }
}

resource "aquasec_notification" "jira_with_token" {
    name = "jira-example-with-token"
    type = "jira"
    properties = {
        url = "<JIRA-URL>"
        token = "<JIRA-TOKEN>"
        project_key = "<JIRA_PROJECT_KEY>"
        summary = "SOME_TEXT"
        definition_of_done = "Done"
    }
}

resource "aquasec_notification" "jira_with_creds" {
    name = "jira-example-with-creds"
    type = "jira"
    properties = {
        url = "<JIRA-URL>"
        user = "<JIRA_USERNAME>"
        password = "<JIRA_PASSWORD>"
        project_key = "<JIRA_PROJECT_KEY>"
        summary = "SOME_TEXT"
    }
}

resource "aquasec_notification" "email_with_creds" {
    name = "email-example-with-creds"
    type = "email"
    properties = {
        user = "<EMAIL_USERNAME>"
        password = "<EMAIL_PASSWORD>"
        host = "<EMAIL_HOST>"
        port = "<EMAIL_PORT>" # example 25
        sender = "<SENDER_EMAIL_ADDRESS>"
        recipients = "<RECIPIENTS>" # "example1@example.com,example2@example.com"
    }
}

resource "aquasec_notification" "email_with_mx" {
    name = "email-example-with-mx"
    type = "email"
    properties = {
        use_mx = true
        port = "<EMAIL_PORT>" # example 25
        sender = "<SENDER_EMAIL_ADDRESS>"
        recipients = "<RECIPIENTS>" # "example1@example.com,example2@example.com"
    }
}