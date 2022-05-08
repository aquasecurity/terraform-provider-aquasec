resource "aquasec_enforcer_groups" "group" {
    group_id = "IacGroup"
    type = "agent"
    orchestrator {}
}