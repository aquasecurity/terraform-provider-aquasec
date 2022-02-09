terraform {
  required_providers {
    aquasec = {
      version = "0.8.5"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
username = "IaC"                    // Alternatively sourced from $AQUA_USER
  aqua_url = "https://aquaurl.com"  // Alternatively sourced from $AQUA_URL
  password = "@password"            // Alternatively sourced from $AQUA_PASSWORD

  // If you are using unverifiable certificates (e.g. self-signed) you may need to disable certificate verification
  verify_tls = false                // Alternatively sourced from $AQUA_TLS_VERIFY

  // Alternatively, you can provide these configurations from a config file, and configure the provider as below
  // config_path = '/path/to/tf.config' // defaults to '~/.aqua/tf.config' -- Alternatively sourced from $AQUA_CONFIG
}
