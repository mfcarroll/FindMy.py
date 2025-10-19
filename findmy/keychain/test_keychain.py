import os
import sys
import asyncio
import requests
import getpass
from typing import cast, Any

# Import the main (async) account class
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.state import LoginState
from findmy.reports.anisette import get_provider_from_mapping, AnisetteMapping
from findmy.reports.twofactor import (
    AsyncSmsSecondFactor,
    AsyncTrustedDeviceSecondFactor,
)
from findmy.keychain.escrow import EscrowClient
from findmy.keychain.keychain_access import KeychainAccess
from findmy.keychain.cloudkit_session import CloudKitSession


async def main():
    """Runs the full login, escrow recovery, and keychain fetch."""

    try:
        apple_id = input("Enter Apple ID: ")
        password = getpass.getpass("Enter Password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nLogin cancelled.")
        sys.exit(1)
        
    print(f"Logging in to {apple_id}...")

    # --- 1. REPORTS: AUTHENTICATION (Async) ---
    
    anisette_mapping = cast(AnisetteMapping, {"type": "aniLocal", "prov_data": None})
    anisette = get_provider_from_mapping(anisette_mapping)
    
    acc = AsyncAppleAccount(anisette=anisette)
    
    # We can now use the high-level login() method
    state = await acc.login(apple_id, password)

    # 1b. Handle 2FA
    if state == LoginState.REQUIRE_2FA:
        print("2FA required.")
        methods = await acc.get_2fa_methods()
        if not methods:
            print("No 2FA methods found.")
            await acc.close()
            sys.exit(1)

        print("Select a 2FA method:")
        for i, method in enumerate(methods):
            if isinstance(method, AsyncSmsSecondFactor):
                print(f"  {i}: SMS ({method.phone_number})")
            elif isinstance(method, AsyncTrustedDeviceSecondFactor):
                print(f"  {i}: Trusted Device")

        try:
            idx = int(input(f"Enter choice (0-{len(methods)-1}): "))
            method = methods[idx]
        except (ValueError, IndexError, EOFError, KeyboardInterrupt):
            print("\nInvalid selection or cancelled.")
            await acc.close()
            sys.exit(1)

        await method.request()
        
        try:
            code = input("Enter 2FA code: ")
        except (EOFError, KeyboardInterrupt):
            print("\n2FA cancelled.")
            await acc.close()
            sys.exit(1)
            
        # The high-level submit() is now fine to use
        state = await method.submit(code)

    if state != LoginState.LOGGED_IN:
        print(f"Login failed with final state: {state}")
        await acc.close()
        sys.exit(1)
        
    print("Login successful. Extracting tokens...")

    # --- 2. ESCROW: MASTER KEY RECOVERY (Async) ---

    # Extract data using the modified structure in account.py
    mobileme_data = acc._login_state_data["mobileme_data"]
    config_data = acc._login_state_data.get("config", {}) # Get the saved config dict
    dsid = acc._login_state_data["dsid"]
    tokens = mobileme_data["tokens"] 
    mme_auth_token = tokens["mmeAuthToken"]
    
    # --- ADD DEBUG PRINT ---
    print("--- DEBUG: Config Data ---")
    import pprint
    pprint.pprint(config_data)
    print("--- END DEBUG ---")
    # --- END ADDITION ---

    keychain_sync_config = config_data.get("com.apple.Dataclass.KeychainSync", {})
    escrow_host = keychain_sync_config.get("escrowProxyUrl")
    
    if not escrow_host:
        print("ERROR: Could not find 'escrowProxyUrl' in login response config.")
        # Optional: Print the config_data for further debugging if needed
        # print("--- DEBUG: Config Data ---")
        # import pprint
        # pprint.pprint(config_data)
        # print("--- END DEBUG ---")
        await acc.close()
        sys.exit(1)

    pet_token = acc.idms_pet
    
    if not pet_token:
        print("Failed to get 'idms_pet' (pet_token) from account object.")
        await acc.close()
        sys.exit(1)
    
    aiohttp_session = await acc._http._get_session()

    escrow_client = EscrowClient(
        session=aiohttp_session,
        anisette=anisette,
        dsid=dsid,
        username=apple_id,
        pet_token=pet_token, 
        mme_auth_token=mme_auth_token,
        escrow_host=escrow_host, # Use the correctly extracted host
    )

    try:
        print("Recovering MasterKey from escrow...")
        master_key_pem = await escrow_client.recover_master_key(password)
        print("Successfully recovered MasterKey.")
    except Exception as e:
        print(f"Failed to recover MasterKey: {e}")
        await acc.close()
        sys.exit(1)
        
    await acc.close()

    # --- 3. CLOUDKIT: FETCH SECRETS (Sync) ---
    
    print("Initializing sync CloudKit session...")
    
    ck_token = tokens["searchPartyToken"]
    
    def get_secrets_sync() -> list:
        req_session = requests.Session()

        ck_session = CloudKitSession(
            dsid=dsid,
            ck_token=ck_token,
            session=req_session,
            anisette_provider=anisette,
        )

        kc = KeychainAccess(ck_session)
        kc.keystore["MasterKey"] = master_key_pem
        return kc.get_device_secrets()

    try:
        keychain_items = await asyncio.to_thread(get_secrets_sync)
        
        print("---")
        print(f"Successfully fetched keychain. Found {len(keychain_items)} items.")
        for item in keychain_items:
            print(f"- Item (acct: {item.get('acct')}, svce: {item.get('svce')})")

    except Exception as e:
        print(f"Failed to fetch keychain secrets: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())