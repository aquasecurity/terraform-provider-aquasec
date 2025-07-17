# Terraform Provider Scaffolding

This repository is a *template* for a [Terraform](https://www.terraform.io) provider. It is intended as a starting point for creating Terraform providers, containing:

 - A resource, and a data source (`internal/provider/`),
 - Examples (`examples/`) and generated documentation (`docs/`),
 - Miscellanious meta files.

These files contain boilerplate code that you will need to edit to create your own Terraform provider. A full guide to creating Terraform providers can be found at [Writing Custom Providers](https://www.terraform.io/docs/extend/writing-custom-providers.html).

Please see the [GitHub template repository documentation](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/creating-a-repository-from-a-template) for how to create a new repository from this template on GitHub.

Once you've written your provider, you'll want to [publish it on the Terraform Registry](https://www.terraform.io/docs/registry/providers/publishing.html) so that others can use it.


## Requirements

-	[Terraform](https://www.terraform.io/downloads.html) >= 0.13.x
-	[Go](https://golang.org/doc/install) >= 1.18

## Build the Aquasec Provider

The Aquasec Terraform provider can be pulled from the [Hashicorp registry](https://registry.terraform.io/providers/aquasecurity/aquasec/latest) as for the included examples in this repository.

As an alternative, and for development purposes, you can build the provider locally with the following instructions.

**Clone the repo**

Clone the repository locally and switch to the version you want to try
```
git clone https://github.com/aquasecurity/terraform-provider-aquasec.git

cd terraform-provider-aquasec

git checkout v0.8.41
```

**Build and install the provider**
```
make build install
```

The last command will compile the Terraform Provider and generate a `terraform-provider-aquasec` binary in your local directory and then will install into the folder containing the Terraform resources.

**Install the provider**

After a successful build, the generated binary will need to be installed into the folder containing the Terraform resources.

We'll use here the [example Terraform resources](examples/resources/main.tf) provided in this repo.

**Terraform configuration**

In order to test the provider installed locally, the provider block will have to include the path to the current binary, as in the following example
```
terraform {
  required_providers {
    aquasec = {
      version = "7"
      source  = "terraform-provider-aquasec/aquasec/aquasec"
    }
  }
}
```

## Test Aquasec Terraform Provider

Now you can carry on initialising Terraform in your folder with the resources.
This step will be very shortly since Terraform won't download the provider but use instead the local binary

```
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

## Documentation generation

This will allow you to locally generate updates to the documentation (found in the `docs` directory).
```sh
go install github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs # check source url in tools/tools.go
```
Ensure `GOBIN` is set correctly, or that the installed `tfplugindocs` tool is available on your `PATH`.
```sh
which tfplugindocs # if not found, check in your $GOPATH/bin/tfplugindocs
```

Ensure you are in the root directory of the project, and run
```sh
tfplugindocs generate
```

The tool will analyse the source code, and automatically build a schema map, with `Description` fields allowing for
some additional context to be provided. It will also iterate through template files in `templates/`, and example code for
each resource can be provided at `examples/resources/[full resource name]/resource.tf`. Similarly, for data sources,
the location is `examples/data-sources/[full data source name]/data-source.tf`.

The output in the docs directory is what gets published on https://registry.terraform.io. Please take care to provide
quality documentation and examples of resources and data sources developed for the provider.
