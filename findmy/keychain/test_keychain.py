import os
import sys
import asyncio
import requests
import getpass  # --- Use getpass for interactive password prompt ---
from typing import cast, Any

# --- Service 1: Reports (for Auth) ---
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.state import LoginState
from findmy.reports.anisette import get_provider_from_mapping, AnisetteMapping
from findmy.reports.twofactor import (
    AsyncSmsSecondFactor,
    AsyncTrustedDeviceSecondFactor,
)

# --- Service 2: Escrow (for MasterKey) ---
from findmy.keychain.escrow import EscrowClient

# --- Service 3: CloudKit (for Secrets) ---
from findmy.keychain.keychain_access import KeychainAccess
from findmy.keychain.cloudkit_session import CloudKitSession


async def main():
    """Runs the full login, escrow recovery, and keychain fetch."""

    # --- Use interactive login instead of os.environ ---
    try:
        apple_id = input("Enter Apple ID: ")
        password = getpass.getpass("Enter Password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nLogin cancelled.")
        sys.exit(1)
        
    print(f"Logging in to {apple_id}...")

    # --- 1. REPORTS: AUTHENTICATION (Async) ---
    
    anisette_mapping = cast(AnisetteMapping, {"type": "native"})
    anisette = get_provider_from_mapping(anisette_mapping)
    
    acc = AsyncAppleAccount(anisette=anisette)
    
    # 1a. GSA Authenticate (Pass interactive credentials)
    try:
        state = await acc._gsa_authenticate(apple_id, password)
    except Exception as e:
        print(f"GSA Authentication failed: {e}")
        await acc.close()
        sys.exit(1)

    pet_token = acc._login_state_data.get("idms_pet")
    if not pet_token:
        print("Failed to get 'idms_pet' (pet_token) from GSA auth.")
        await acc.close()
        sys.exit(1)

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
            
        state = await method.submit(code)

    # 1c. MobileMe Login
    if state == LoginState.AUTHENTICATED:
        state = await acc._login_mobileme()

    if state != LoginState.LOGGED_IN:
        print(f"Login failed with final state: {state}")
        await acc.close()
        sys.exit(1)
        
    print("Login successful. Extracting tokens...")

    # --- 2. ESCROW: MASTER KEY RECOVERY (Async) ---

    dsid = acc._login_state_data["dsid"]
    service_data = acc._login_state_data["mobileme_data"]["service-data"]
    tokens = acc._login_state_data["mobileme_data"]["tokens"]
    mme_auth_token = tokens["mmeAuthToken"]
    escrow_host = service_data["escrowHost"]
    
    aiohttp_session = await acc._http._get_session()

    escrow_client = EscrowClient(
        session=aiohttp_session,
        anisette=anisette,
        dsid=dsid,
        username=apple_id,
        pet_token=pet_token,
        mme_auth_token=mme_auth_token,
        escrow_host=escrow_host,
    )

    try:
        print("Recovering MasterKey from escrow...")
        # Pass the interactive password to the escrow client
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
            # The final decrypted item is a plist (dict)
            print(f"- Item (acct: {item.get('acct')}, svce: {item.get('svce')})")

    except Exception as e:
        print(f"Failed to fetch keychain secrets: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())