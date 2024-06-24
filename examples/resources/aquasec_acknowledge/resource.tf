resource "aquasec_acknowledge" "acknowledge" {
  comment = "comment"
  issues {
    docker_id        = ""
    image_name       = "image:latest"
    issue_name       = "CVE-2022-1271"
    issue_type       = "vulnerability"
    registry_name    = "registry"
    resource_cpe     = "cpe:/a:gnu:gzip:1.10"
    resource_name    = "gzip"
    resource_path    = "/usr/bin/gzip"
    resource_type    = "executable"
    resource_version = "1.10"
  }

  issues {
    docker_id        = "docker-id"
    image_name       = "image-name"
    issue_name       = "ALAS2-2021-1722"
    issue_type       = "vulnerability"
    registry_name    = "registry-name"
    resource_cpe     = "pkg:/amzn:2:nss-softokn:3.44.0-8.amzn2"
    resource_name    = "nss-softokn"
    resource_path    = ""
    resource_type    = "package"
    resource_version = "3.44.0-8.amzn2"
  }
}
