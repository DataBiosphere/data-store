data "aws_caller_identity" "current" {}

locals {
  common_tags = "${map(
    "managedBy" , "terraform",
    "Name"      , "${var.DSS_INFRA_TAG_SERVICE}-acldynamodb",
    "project"   , var.DSS_INFRA_TAG_PROJECT,
    "env"       , var.DSS_DEPLOYMENT_STAGE,
    "service"   , var.DSS_INFRA_TAG_SERVICE,
    "owner"     , var.DSS_INFRA_TAG_OWNER
  )}"
}

resource "aws_dynamodb_table" "sfn_state" {
  name         = "dss-auth-lookup-${var.DSS_DEPLOYMENT_STAGE}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "hash_key"

  point_in_time_recovery {
    enabled = true
  }

  attribute {
    name = "hash_key"
    type = "S"
  }

  attribute {
    name = "owner"
    type = "S"
  }

  attribute {
    name = "groups"
    type = "L"
  }

  attribute {
    name = "roles"
    type = "L"
  }

  tags = local.common_tags
}
