#!/bin/sh

# Function to generate a random string
generate_random_string_with_timestamp() {
    # Generate the timestamp in the desired format
    timestamp=$(TZ='Asia/Kuala_Lumpur' date "+%Y-%m-%d_%H-%M-%S")
    # Concatenate the timestamp and the random string
    echo "${timestamp}_near_recovery"
}

random_account_id="$(generate_random_string_with_timestamp)"
full_account_id="$random_account_id.testnet"

near create-account $full_account_id --useFaucet

echo "$full_account_id" > "$(dirname "$(realpath "$0")")/../neardev/dev-account"

