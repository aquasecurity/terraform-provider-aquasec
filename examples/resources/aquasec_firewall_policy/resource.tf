resource "aquasec_firewall_policy" "example_firewall_policy" {
  // Required values
  name = "example_firewall_policy"

  // Block ICMP and one inbound/outbound block
  block_icmp_ping = true
  inbound_networks {
    allow         = false
    resource_type = "anywhere"
    port_range    = "0-1000"
  }

  outbound_networks {
    allow         = false
    resource_type = "custom"
    port_range    = "0-1000"
    resource      = "192.168.1.5/32"
  }
}