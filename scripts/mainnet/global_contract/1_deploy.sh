export VERSION="v0.0.1"
export CONTRACT_PATH="$(cat "$(dirname "$(realpath "$0")")/../build/$VERSION.wasm")"
export CONTRACT_ID="meteor-recovery.near"

# near contract deploy-as-global use-file $CONTRACT_PATH as-global-account-id $CONTRACT_ID network-config mainnet sign-with-keychain send

# echo "Deploying contract $CONTRACT_ID with version $VERSION..."
near contract deploy-as-global use-file ../build/v0.0.1.wasm as-global-account-id meteor-recovery.near network-config mainnet sign-with-keychain send