resource "aquasec_service" "example_service" {
  name               = "svc_example"
  description        = "Example service with global and local policies"
  target             = "container"
  priority           = 90
  application_scopes = ["Global"]
  enforce            = true

  // Global policies applied to this service
  policies = ["default", "policy1", "policy2"]

  // Local policy 1
  local_policies {
    name        = "policy1"
    type        = "access.control"
    description = "Local policy 1 for inbound and outbound control"

    inbound_networks {
      port_range    = "22/22"    # Allow SSH traffic
      resource_type = "anywhere" # Allow from any source
      allow         = true       # Permit traffic
    }

    outbound_networks {
      port_range    = "80/80"    # Allow HTTP traffic
      resource_type = "anywhere" # Allow to any destination
      allow         = true       # Permit traffic
    }

    block_metadata_service = false # Do not block metadata service
  }

  // Local policy 2
  local_policies {
    name        = "policy2"
    type        = "access.control"
    description = "Local policy 2 with stricter outbound control"

    inbound_networks {
      port_range    = "443/443"  # Allow HTTPS traffic
      resource_type = "anywhere" # Allow from any source
      allow         = true       # Permit traffic
    }

    outbound_networks {
      port_range    = "8080/8080" # Allow specific application traffic
      resource_type = "specific"  # Allow only to specific destinations
      allow         = false       # Block traffic to unspecified destinations
    }

    block_metadata_service = true # Block metadata service access for security
  }
}
