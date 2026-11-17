path "ci/data/build/*" { capabilities = ["read"] }
path "ci/data/build/private/*" { capabilities = ["deny"] }
path "ci/metadata/build" { capabilities = ["list"] }
path "legacy/release" {
  capabilities = ["create", "update"]
  required_parameters = ["stage"]
  allowed_parameters = { "stage" = ["test"], "value" = [] }
}
path "legacy/ephemeral" { capabilities = ["read", "delete"] }
