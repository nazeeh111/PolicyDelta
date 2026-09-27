path "ci/data/*" { capabilities = ["read"] }
path "ci/data/build/private/*" { capabilities = ["deny"] }
path "ci/metadata/build" { capabilities = ["list"] }
path "legacy/release" { capabilities = ["create", "update"] }
path "legacy/ephemeral" { capabilities = ["read", "delete"] }
