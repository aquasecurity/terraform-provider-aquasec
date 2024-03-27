resource "aquasec_application_scope" "terraformiap" {
  description = "test123"
  name        = "test18"
  // Categories is a nested block of artifacts, workloads and infrastructure
  categories {
    // Artifacts is a nested block of Image, Function, CF
    artifacts {
      // Every object requires expression(logical combinations of variables v1, v2, v3...) and list of variables consists of attribute(pre-defined) and value
      image {
        expression = "v1 && v2"
        variables {
          attribute = "aqua.registry"
          value     = "test-registry"
        }
        variables {
          attribute = "image.repo"
          value     = "nginx"
        }
      }
    }
    // Workloads is a nested block of Kubernetes, OS, CF
    workloads {
      // Every object requires expression(logical combinations of variables v1, v2, v3...) and list of variables consists of attribute(pre-defined) and value
      kubernetes {
        expression = "v1 && v2"
        variables {
          attribute = "kubernetes.cluster"
          value     = "aqua"
        }
        variables {
          attribute = "kubernetes.namespace"
          value     = "aqua"
        }
      }
    }
    // Infrastructure is a nested block of Kubernetes, OS
    infrastructure {
      // Every object requires expression and list of variables consists of attribute(pre-defined) and value
      kubernetes {
        expression = "v1"
        variables {
          attribute = "kubernetes.cluster"
          value     = "aqua"
        }
      }
    }
  }
}