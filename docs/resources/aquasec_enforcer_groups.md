---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "aquasec_enforcer_groups Resource - fork-terraform-provider-aquasec"
subcategory: ""
description: |-
  
---

# Resource `aquasec_enforcer_groups`



## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **group_id** (String) The ID of the Enforcer group.
- **orchestrator** (Block Set, Min: 1) The orchestrator for which you are creating the Enforcer group. (see [below for nested schema](#nestedblock--orchestrator))
- **type** (String) Enforcer Type.

### Optional

- **admission_control** (Boolean) Selecting this option will allow the KubeEnforcer to block the deployment of container images that have failed any of these Container Runtime Policy controls:\
				* Block Non-Compliant Images\
				* Block Non-Compliant Workloads\
				* Block Unregistered Images\
				This functionality can work only when the KubeEnforcer is deployed in Enforce mode.
- **allow_kube_enforcer_audit** (Boolean) Allow kube enforcer audit.
- **allowed_applications** (Set of String) List of application names to allow on the hosts. if provided, only containers of the listed applications will be allowed to run.
- **allowed_labels** (Set of String) List of label names to allow on the hosts.
- **allowed_registries** (Set of String) List of registry names to allow on the hosts.
- **antivirus_protection** (Boolean) This setting is available only when you have license for `Advanced Malware Protection`. Send true to make use of the license and enable the `Real-time Malware Protection` control in the Host Runtime policies.
- **audit_all** (Boolean) Agent will send extra audit messages to the server for success operations from inside the container (runtime).
- **auto_copy_secrets** (Boolean) This option is applicable only if `Enable Pod Enforcer injection` is selected. Select this option if you want Aqua Enterprise to copy the secrets defined above to the Pod Enforcer namespace and container. Otherwise, you can choose to copy these secrets by other means.
- **auto_discover_configure_registries** (Boolean) This option is available only if `Enable workload discovery` is selected. If selected, the KubeEnforcer will add previously unknown image registries from the cluster to Aqua.
- **auto_discovery_enabled** (Boolean) When this option is selected, the KubeEnforcer will discover workloads on its cluster.
- **auto_scan_discovered_images_running_containers** (Boolean) This option is available only if `Enable workload discovery` is selected. If selected, the KubeEnforcer will automatically register images running as workloads (and scan the discovered images for security issues).
- **behavioral_engine** (Boolean) Select Enabled to detect suspicious activity in your containers and display potential security threats in the Incidents and Audit pages.
- **block_admission_control** (Boolean) This applies only if both `Enable admission control` and Enforce mode are set. This additional option must be selected for admission control to work if the KubeEnforcer is not connected to any Gateway. If this option is not selected, admission control will be disabled; this will have no effect on containers already running.
- **container_activity_protection** (Boolean) Set `true` to apply Container Runtime Policies, Image Profiles, and Firewall Policies to containers.
- **container_antivirus_protection** (Boolean) This setting is available only when you have license for `Advanced Malware Protection`. Send true to make use of the license and enable the `Real-time Malware Protection` control in the Container Runtime policies.
- **description** (String) A description of the Aqua Enforcer group.
- **enforce** (Boolean) Whether to enable enforce mode on the Enforcers, defaults to False.
- **gateways** (List of String) List of Aqua gateway IDs for the Enforcers.
- **host_assurance** (Boolean) Set `True` to enable host scanning and respective Host Assurance controls.
- **host_behavioral_engine** (Boolean) Set `True` to enable these Host Runtime Policy controls: `OS Users and Groups Allowed` and `OS Users and Groups Blocked`
- **host_network_protection** (Boolean) Set `True` to apply Firewall Policies to hosts, and allow recording network maps for Aqua services. The Network Firewall setting must be disabled when deploying the Aqua Enforcer on a machine running Rocky Linux. See https://docs.aquasec.com/docs/platform-support-limitations-rocky-linux for further information
- **host_os** (String) The OS type for the host
- **host_protection** (Boolean) Set `True` to enable all Host Runtime Policy controls except for `OS Users and Groups Allowed` and `OS Users and Groups Blocked`.
- **host_user_protection** (Boolean) Set `True` to enable these Host Runtime Policy controls: `OS Users and Groups Allowed` and `OS Users and Groups Blocked`
- **id** (String) The ID of this resource.
- **image_assurance** (Boolean) Set `True` to enable selected controls: Container Runtime Policy (`Block Non-Compliant Images`, `Block Unregistered Images`, and `Registries Allowed`) and Default Image Assurance Policy (`Images Blocked`).
- **kube_bench_image_name** (String) See https://docs.aquasec.com/docs/securing-kubernetes-applications#section-configuration-hardening, The KubeEnforcer can deploy the Aqua Security kube-bench open-source product to perform Kubernetes CIS benchmark testing of nodes.
				This field specifies the path and file name of the kube-bench product image for the KubeEnforcer to deploy; it will be filled in automatically. You can optionally enter a different value.
- **logical_name** (String) Name for the batch install record.
- **micro_enforcer_certs_secrets_name** (String) This option is applicable only if `Enable Pod Enforcer injection` is selected.
- **micro_enforcer_image_name** (String) This option is applicable only if `Enable Pod Enforcer injection` is selected. This field specifies the path and file name of the KubeEnforcer product image to be deployed; it will be filled in automatically. You can optionally enter a different value.
- **micro_enforcer_injection** (Boolean) This applies only if both `Enable admission control` and Enforce mode are set. This additional option must be selected for admission control to work if the KubeEnforcer is not connected to any Gateway. If this option is not selected, admission control will be disabled; this will have no effect on containers already running.
- **micro_enforcer_secrets_name** (String) You can specify the name of the secret (in the Aqua namespace) that Aqua copies into the Pod Enforcer namespace and kube-bench, allowing them access to the Pod Enforcer and kube-bench product images, respectively.
- **network_protection** (Boolean) Send true to apply Firewall Policies to containers, and allow recording network maps for Aqua services. The Network Firewall setting must be disabled when deploying the Aqua Enforcer on a machine running Rocky Linux. See https://docs.aquasec.com/docs/platform-support-limitations-rocky-linux for further information.
- **permission** (String) Permission Action
- **risk_explorer_auto_discovery** (Boolean) Set `true` to allow Enforcers to be discovered in the Risk Explorer.
- **runtime_type** (String) The container runtime environment.
- **sync_host_images** (Boolean) Set `true` to configure Enforcers to discover local host images. Discovered images will be listed under Images > Host Images, as well as under Infrastructure (in the Images tab for applicable hosts).
- **syscall_enabled** (Boolean) Set `true` will allow profiling and monitoring system calls made by running containers.
- **user_access_control** (Boolean) Set `true` to apply User Access Control Policies to containers. Note that Aqua Enforcers must be deployed with the AQUA_RUNC_INTERCEPTION environment variable set to 0 in order to use User Access Control Policies.

### Read-only

- **aqua_version** (String) Aqua server version
- **command** (List of Object) The installation command. (see [below for nested schema](#nestedatt--command))
- **connected_count** (Number) Number of connected enforcers in the enforcer group.
- **disconnected_count** (Number) Number of disconnected enforcers in the enforcer group.
- **enforcer_image_name** (String) The specific Aqua Enforcer product image (with image tag) to be deployed.
- **gateway_address** (String) Gateway Address
- **gateway_name** (String) Gateway Name
- **high_vulns** (Number) Number of high vulnerabilities in the enforcers that in this enforcer group.
- **hostname** (String) The hostname
- **hosts_count** (Number) Number of enforcers in the enforcer group.
- **install_command** (String) Enforcer install command
- **last_update** (Number) The last date and time the batch token was updated in UNIX time.
- **low_vulns** (Number) Number of low vulnerabilities in the enforcers that in this enforcer group.
- **med_vulns** (Number) Number of medium vulnerabilities in the enforcers that in this enforcer group.
- **neg_vulns** (Number) Number of negligible vulnerabilities in the enforcers that in this enforcer group.
- **pas_deployment_link** (String) pas deployment link
- **runtime_policy_name** (String) Function Runtime Policy that will applay on the nano enforcer.
- **token** (String) The batch install token.

<a id="nestedblock--orchestrator"></a>
### Nested Schema for `orchestrator`

Optional:

- **master** (Boolean)
- **namespace** (String) May be specified for these orchestrators: Kubernetes, Kubernetes GKE, VMware Tanzu Kubernetes Grid Integrated Edition (PKS).
- **service_account** (String) May be specified for these orchestrators: Kubernetes, Kubernetes GKE, OpenShift, VMware Tanzu Kubernetes Grid Integrated Edition (PKS).
- **type** (String)


<a id="nestedatt--command"></a>
### Nested Schema for `command`

Read-only:

- **default** (String)
- **kubernetes** (String)
- **swarm** (String)
- **windows** (String)

