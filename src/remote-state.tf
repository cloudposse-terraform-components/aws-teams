module "aws_saml" {
  source  = "cloudposse/stack-config/yaml//modules/remote-state"
  version = "1.8.0"

  component  = var.aws_saml_component_name
  privileged = true

  ignore_errors = true

  defaults = {
    saml_provider_assume_role_policy = ""
  }

  context = module.this.context
}

module "account_map" {
  source  = "cloudposse/stack-config/yaml//modules/remote-state"
  version = "1.8.0"

  component   = var.account_map_component_name
  tenant      = module.iam_roles.global_tenant_name
  environment = module.iam_roles.global_environment_name
  stage       = module.iam_roles.global_stage_name
  privileged  = true

  context = module.this.context
}
