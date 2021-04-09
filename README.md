<a href="https://terraform.io">
    <img src="https://www.terraform.io/assets/images/og-image-8b3e4f7d.png" alt="Terraform logo" title="Terraform" height="100" />
</a>
<a href="https://www.aquasec.com/">
    <img src="https://avatars3.githubusercontent.com/u/12783832?s=200&v=4" alt="Aqua logo" title="Aquasec" height="100" />
</a>

Aquasec Provider for Terraform
===========================

This is the Aquasec provider for [Terraform](https://www.terraform.io/).

Useful links:
- [Aqua Documentation](https://docs.aquasec.com)
- [Terraform Documentation](https://www.terraform.io/docs/language/index.html)
- [Terraform Provider Development](DEVELOPMENT.md)

The provider lets you declaratively define the configuration for your Aqua Enterprise platform.


## Contents

* [Requirements](#requirements)
* [Build the Provider](#build-the-aquasec-provider)
* [Install and Test Locally](#Install-and-Test-the-Provider-Locally)
* [Contributing](#contributing)


## Requirements

-	[Terraform](https://www.terraform.io/downloads.html) v0.12.x or higher
-	[Go](https://golang.org/doc/install) v1.16.x (to build the provider plugin)
- [Aqua Enterprise Plaatform](https://www.aquasec.com/aqua-cloud-native-security-platform/)


## Build the Aquasec Provider

Clone the repository locally and switch to the version you want to try
```
git clone https://github.com/aquasecurity/terraform-provider-aquasec.git

cd terraform-provider-aquasec

git checkout v0.6
```

Build the provider
```
go build
```

The last command will compile the Terraform Provider and generate a `terraform-provider-aquasec` binary in your local directory.

## Install and Test the Provider Locally

After [building the provider](#build-the-aquasec-provider), the generated binary will need to be installed into the folder containing the Terraform resources.

We'll use here the [example Terraform resources](examples/resources/main.tf) provided in this repo.

```
mkdir -p examples/resources/.terraform/plugins/terraform-provider-aquasec/aquasec/aquasec/0.6/darwin_amd64/

mv terraform-provider-aquasec examples/resources/.terraform/plugins/terraform-provider-aquasec/aquasec/aquasec/0.6/darwin_amd64/terraform-provider-aquasec
```
Make sure to replace the version `0.6` and the architecture `darwin_amd64` in the path as relevant for your system.

In order to test the provider installed locally, the provider block will have to include the path to the current binary, as in the following example
```
terraform {
  required_providers {
    aquasec = {
      version = "0.6"
      source  = "terraform-provider-aquasec/aquasec/aquasec"
    }
  }
}
```
Once applied the change above, move to the resources folder and initialise Terraform
```
cd examples/resources

terraform init
```

Finally, make sure to replace the Aqua credentials and URL in the `provider` block and start trying out the different resources as provided in the example file.

```
provider "aquasec" {
  username = "admin"
  aqua_url = "https://aquaurl.com"
  password = "@password"
}
```

## Contributing

The Aqua Provider for Terraform is the work of many contributors. We appreciate your help!

To contribute, please read the [contribution guidelines](CONTRIBUTING.md). You may also [report an issue](https://github.com/aquasecurity/terraform-provider-aquasec/issues/new/choose). Once you've filed an issue.