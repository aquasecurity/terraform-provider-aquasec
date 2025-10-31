terraform {
  required_providers {
    aquasec = {
      version = "0.11.0"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
  username = "IaC"                 // Alternatively sourced from $AQUA_USER
  aqua_url = "https://aquaurl.com" // Alternatively sourced from $AQUA_URL
  password = "@password"           // Alternatively sourced from $AQUA_PASSWORD

  // If you are using unverifiable certificates (e.g. self-signed) you may need to disable certificate verification
  verify_tls = false // Alternatively sourced from $AQUA_TLS_VERIFY

  // Alternatively, you can provide these configurations from a config file, and configure the provider as below
  // config_path = '/path/to/tf.config' // defaults to '~/.aquasec/tf.config' -- Alternatively sourced from $AQUA_CONFIG
  // validate = false // Skip provider credential validation

  //Alternatively, you can use API key authentication as below instead of username/password authentication.
  aqua_api_key      = var.aquasec_api_key    // Alternatively sourced from $AQUA_API
  aqua_api_secret   = var.aquasec_api_secret // Alternatively sourced from $AQUA_SECRET
  validity          = 240                    // Alternatively sourced from $AQUA_TOKEN_VALIDITY
  allowed_endpoints = ["ANY"]                // Alternatively sourced from $AQUA_ALLOWED_ENDPOINTS
  csp_roles         = ["Admin"]              // Alternatively sourced from $AQUA_CSP_ROLES
}
