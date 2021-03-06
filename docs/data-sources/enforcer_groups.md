---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "aquasec_enforcer_groups Data Source - terraform-provider-aquasec"
subcategory: ""
description: |-
  
---

# Data Source `aquasec_enforcer_groups`





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **group_id** (String)

### Optional

- **id** (String) The ID of this resource.

### Read-only

- **allowed_applications** (Set of String)
- **allowed_labels** (Set of String)
- **allowed_registries** (Set of String)
- **command** (List of Object) (see [below for nested schema](#nestedatt--command))
- **description** (String)
- **enforce** (Boolean)
- **gateway_address** (String)
- **gateway_name** (String)
- **gateways** (List of String)
- **logical_name** (String)
- **orchestrator** (List of Object) (see [below for nested schema](#nestedatt--orchestrator))
- **token** (String)
- **type** (String)

<a id="nestedatt--command"></a>
### Nested Schema for `command`

Read-only:

- **default** (String)
- **kubernetes** (String)
- **swarm** (String)
- **windows** (String)


<a id="nestedatt--orchestrator"></a>
### Nested Schema for `orchestrator`

Read-only:

- **master** (Boolean)
- **namespace** (String)
- **service_account** (String)
- **type** (String)


