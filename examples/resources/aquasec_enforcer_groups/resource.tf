resource "aquasec_enforcer_groups" "group" {
    group_id = "tf-test-enforcer"
    type = "agent"
    enforce = true
    # Host Assurance
    host_assurance = true
    # Network Firewall (Host Protection)
    host_network_protection = true
    # Runtime Controls
    host_protection = true
    # Network Firewall (Container Protection)
    network_protection = true
    # Advanced Malware Protection (Container Protection)
    container_antivirus_protection = true
    # Runtime Controls
    container_activity_protection = true
    # Image Assurance
    image_assurance = true
    # Advanced Malware Protection (Host Protection)
    antivirus_protection = true
    # Host Images
    sync_host_images = true
    # Risk Explorer
    risk_explorer_auto_discovery = true
    orchestrator {}
}

resource "aquasec_enforcer_groups" "group-kube_enforcer" {
    group_id = "tf-test-kube_enforcer"
    type = "kube_enforcer"
    enforce = true

    # Enable admission control
    admission_control = true
    # Perform admission control if not connected to a gateway
    block_admission_control = true
    # Enable workload discovery
    auto_discovery_enabled = true
    # Register discovered pod images
    auto_scan_discovered_images_running_containers = true
    # Add discovered registries
    auto_discover_configure_registries = true
    # Kube-bench image path
    kube_bench_image_name = "registry.aquasec.com/kube-bench:v0.6.5"
    # Secret that holds the registry credentials for the Pod Enforcer and kube-bench
    micro_enforcer_secrets_name = "aqua-registry"
    # Auto copy these secrets to the Pod Enforcer namespace and container
    auto_copy_secrets = true

    orchestrator {
        type = "kubernetes"
        namespace = "aqua"
    }
}