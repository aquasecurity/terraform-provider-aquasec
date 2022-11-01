<a href="https://terraform.io">
    <img src="Terraform_PrimaryLogo_Color_RGB.png" alt="Terraform logo" title="Terraform" height="100" />
</a>
<a href="https://www.aquasec.com/">
    <img src="https://avatars3.githubusercontent.com/u/12783832?s=200&v=4" alt="Aqua logo" title="Aquasec" height="100" />
</a>

Aquasec Provider for Terraform
===========================

This is the Aquasec provider for [Terraform](https://www.terraform.io/).

Useful links:
- [Aqua Documentation](https://docs.aquasec.com)
- [Aquasec Provider Documentation](https://registry.terraform.io/providers/aquasecurity/aquasec/latest/docs)
- [Terraform Documentation](https://www.terraform.io/docs/language/index.html)
- [Terraform Provider Development](DEVELOPMENT.md)

The provider lets you declaratively define the configuration for your Aqua Enterprise platform.


## Contents

* [Requirements](#requirements)
* [Using the Aquasec provider](#Using_the_Aquasec_provider)
* [Contributing](#contributing)


## Requirements

-	[Terraform](https://www.terraform.io/downloads.html) v0.12.x or higher
-	[Go](https://golang.org/doc/install) v1.16.x (to build the provider plugin)
- [Aqua Enterprise Platform](https://www.aquasec.com/aqua-cloud-native-security-platform/)

## Using the Aquasec provider

To quickly get started using the Aquasec provider for Terraform, configure the provider as shown below. Full provider documentation with details on all options available is located on the [Terraform Registry site](https://registry.terraform.io/providers/aquasecurity/aquasec/latest/docs).

```hcl
terraform {
  required_providers {
    aquasec = {
      version = "0.8.17"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
  username = "IaC"
  aqua_url = "https://aquaurl.com"
  password = "@password"
}
```
## Using the Aquasec provider SaaS solution

To quickly get started using the Aquasec SaaS provider for Terraform, configure the provider as shown above. The aqua_url should point to cloud.aquasec.com for the Aqua Customers and the Dev/QA Teams need to provide their Urls respectively.

**_NOTE:_**  SaaS authentication is supported from version 0.8.4+

## Contributing

The Aqua Provider for Terraform is the work of many contributors. We appreciate your help!

To contribute, please read the [contribution guidelines](CONTRIBUTING.md). You may also [report an issue](https://github.com/aquasecurity/terraform-provider-aquasec/issues/new/choose). Once you've filed an issue.
