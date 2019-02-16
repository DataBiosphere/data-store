locals {
  replicas = ["aws", "gcp"]
} 

resource "aws_dynamodb_table" "subscriptions-aws" {
  count        = "${length(local.replicas)}"
  name         = "dss-subscriptions-v2-${local.replicas[count.index]}-${var.DSS_DEPLOYMENT_STAGE}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "hash_key"
  range_key    = "sort_key"

  attribute {
    name = "hash_key"
    type = "S"
  }

  attribute {
    name = "sort_key"
    type = "S"
  }

  tags {
    CreatedBy = "Terraform"
    Application = "DSS"
  }
}
