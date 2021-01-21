terraform {
  required_providers {
    aqua = {
      version = "~> 0.0.1"
      source="aquasec.com/field/aqua"
    }
  }
}

provider "aqua" {
  user = "user"
  aqua_url = "http://aqua-url"
  password = "password"
}

resource "aqua_access_management" "terraform" {
  name = "Terraform"
  description = "Created by terraform"

  categories {
    artifacts {
      image {
        expression = "v1 || v2"
        variables {
          attribute = "aqua.registry"
          value = "aquademo"
        }

        variables {
          attribute = "aqua.registry"
          value = "ecr-us-east-1"
        }
      }
      function {
        expression = "v1"
        variables {
          attribute = "aqua.serverless_project"
          value = "lambda-demo"
        }
      }
      cf {}
    }
    workloads {
      kubernetes {
        expression = "v1"
        variables {
          attribute = "kubernetes.namespace"
          value = "sock-shop"
        }
      }
      os {}
      cf {}
    }
    infrastructure {
      kubernetes {
        expression = "v1"
        variables {
          attribute = "kubernetes.cluster"
          value = "demo1772"
        }
      }
      os {}
    }
  }
}

output "new_application_scope" {
  value = aqua_access_management.terraform.name
}
