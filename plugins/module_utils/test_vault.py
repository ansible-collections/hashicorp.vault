import json
import os
import sys

# To run this script, ensure your PYTHONPATH is set correctly so that
# Python can find your collection's modules.
# Example:
# export PYTHONPATH=/path/to/your/collections_root
from ansible_collections.ansible_automation_platform.hashicorp.vault.plugins.module_utils.authentication import (
    TokenAuthenticator,
)
from ansible_collections.ansible_automation_platform.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
)
from ansible_collections.ansible_automation_platform.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultError,
)


def run_vault_tests():
    """
    Initializes a Vault client, then creates, patches, and reads a secret.
    """
    # --- 1. Configuration ---
    vault_address = os.environ.get("VAULT_ADDR")
    vault_namespace = os.environ.get("VAULT_NAMESPACE")
    vault_token = os.environ.get("VAULT_TOKEN")
    print(vault_address, vault_namespace, vault_token)
    if not vault_address or not vault_namespace:
        print(
            "Error: VAULT_ADDR and VAULT_NAMESPACE environment variables must be set."
        )
        sys.exit(1)

    mount_path = "secret"
    secret_path = "sample-secret"
    initial_data = {"owner": "original", "priority": "high"}
    patch_data = {"status": "updated", "priority": "critical"}

    # --- 2. Initialize and Authenticate Client ---
    print(f"Initializing unauthenticated client for Vault at {vault_address}...")
    client = VaultClient(
        vault_address=vault_address, vault_namespace=vault_namespace
    )

    print("Authenticating with token from environment...")
    authenticator = TokenAuthenticator()
    authenticator.authenticate(client, token=vault_token)

    # --- 3. Create or Update Secret ---
    print(f"Attempting to create/update secret at path: '{secret_path}'")
    create_result = client.secrets.kv2.create_or_update_secret(
        mount_path=mount_path, secret_path=secret_path, secret_data=initial_data
    )
    print(f"✅ Create/update operation successful! Version: {create_result.get('version')}")

    # --- 4. Patch the Secret ---
    print(f"Attempting to patch secret at path: '{secret_path}'")
    patch_result = client.secrets.kv2.patch_secret(
        mount_path=mount_path, secret_path=secret_path, secret_data=patch_data
    )
    print(f"✅ Patch operation successful! Version: {patch_result.get('version')}")

    # --- 5. Read and Verify the Secret ---
    print(f"Attempting to read back the secret from path: '{secret_path}'")
    final_secret = client.secrets.kv2.read_secret(
        mount_path=mount_path, secret_path=secret_path
    )
    final_data = final_secret.get("data", {})

    # Verification logic
    expected_data = initial_data.copy()
    expected_data.update(patch_data)

    if final_data == expected_data:
        print("✅ Verification successful! Final data matches expected data.")
    else:
        print("❌ Verification failed! Data mismatch.")
        print(f"Expected: {expected_data}")
        print(f"Got: {final_data}")
        sys.exit(1)

    # --- 6. Print Final Result ---
    print("\n" + "=" * 50)
    print("All Vault operations completed successfully!")
    print("Final secret data:")
    print(json.dumps(final_data, indent=2))
    print("=" * 50 + "\n")


if __name__ == "__main__":
    print ("ENTER")
    run_vault_tests()

