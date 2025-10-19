# findmy/keychain/test_keychain.py
import asyncio
import aiohttp
import requests
import plistlib
import getpass
from typing import cast, TYPE_CHECKING, Any
from yarl import URL

# --- Use correct class names from provided files ---
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.anisette import LocalAnisetteProvider

# --- Import our NEW keychain classes ---
from findmy.keychain.cloudkit_session import CloudKitSession
from findmy.keychain.keychain_access import KeychainAccess
from findmy.keychain.escrow import EscrowClient

# Define the 2FA callback function
async def handle_2fa(device: Any) -> str:
    """Handles the 2FA input prompt."""
    code = input(f"Enter 2FA code sent to device (or via SMS): ")
    return code.strip()

async def main():
    # --- Get credentials securely ---
    apple_id_prompt = input("Enter Apple ID: ")
    password_prompt = getpass.getpass("Enter Password: ")
    # -------------------------------

    # 1. --- Perform login using your existing Account class ---
    print("\nLogging in to iCloud...")

    async with aiohttp.ClientSession() as aio_session:
        anisette = LocalAnisetteProvider()

        # Initialize Account with only anisette
        account = AsyncAppleAccount(
            anisette=anisette
        )

        try:
            # --- FIX: Pass credentials to login method ---
            await account.login(
                apple_id=apple_id_prompt,
                password=password_prompt,
                two_factor_callback=handle_2fa
            )
            # ---------------------------------------------
        except Exception as e:
            print(f"Login failed: {e}")
            import traceback
            traceback.print_exc()
            return

        if not account.account_info: # type: ignore
            print("Login failed (no account info returned).")
            return

        print("Login successful.")

        # --- 2. Extract all required tokens from the Account object ---
        print("Extracting login tokens for Escrow and CloudKit...")
        try:
            dsid = str(account.account_info["dsid"]) # type: ignore
            # --- FIX: Use credentials stored internally by Account (likely in _state) ---
            # Accessing protected members is generally discouraged, but necessary here
            # if apple_id/password aren't exposed publicly after login.
            username = account._state.apple_id # type: ignore
            password_internal = account._state.password # type: ignore
            if not username or not password_internal:
                 raise ValueError("Could not retrieve username/password from account state after login.")
            # -------------------------------------------------------------------------

            mme_delegate = account.delegates["com.apple.mobileme"] # type: ignore
            pet_token = account.tokens["com.apple.gs.idms.pet"] # type: ignore
            mme_auth_token = mme_delegate["tokens"]["mmeAuthToken"]
            escrow_host = mme_delegate["com.apple.mobileme"]["escrowProxyUrl"]

            ck_token_cookie = aio_session.cookie_jar.filter_cookies(URL("https://idmsa.apple.com")).get("ck-token")
            if not ck_token_cookie:
                raise ValueError("ck-token cookie not found after login.")
            ck_token = ck_token_cookie.value

        except (KeyError, AttributeError, ValueError) as e:
            print(f"Failed to get required tokens or credentials from Account object: {e}")
            return

        # --- 3. Run Escrow Recovery to get the MasterKey ---
        print("Performing Escrow Recovery to get MasterKey...")

        escrow = EscrowClient(
            session=aio_session,
            anisette=anisette,
            dsid=dsid,
            username=username, # Use username retrieved from account state
            pet_token=pet_token,
            mme_auth_token=mme_auth_token,
            escrow_host=escrow_host
        )

        try:
             # --- FIX: Use password retrieved from account state ---
            master_key_pem = await escrow.recover_master_key(password=password_internal)
             # ------------------------------------------------------
            print("Successfully retrieved MasterKey!")
        except Exception as e:
            print(f"Failed to get MasterKey: {e}")
            import traceback
            traceback.print_exc()
            return

        # --- 4. Initialize CloudKit and KeychainAccess ---
        print("Initializing CloudKit session...")
        req_session = requests.Session()
        for cookie in aio_session.cookie_jar:
            req_session.cookies.set(
                cookie.key,
                cookie.value,
                domain=cookie["domain"],
                path=cookie["path"]
            )

        ck_session = CloudKitSession(
            dsid=dsid,
            ck_token=ck_token,
            session=req_session,
            anisette_provider=anisette
        )

        keychain = KeychainAccess(ck_session)

        # --- 5. SEED THE KEYSTORE ---
        keychain.keystore["MasterKey"] = master_key_pem
        print("Keystore seeded with MasterKey.")

        # --- 6. RUN THE FINAL TEST ---
        try:
            print("Attempting to retrieve device secrets from iCloud Keychain...")
            secrets = await asyncio.to_thread(keychain.get_device_secrets)

            if secrets:
                print(f"\n--- SUCCESS: Found {len(secrets)} device secrets ---")
                for i, secret_plist in enumerate(secrets):
                    print(f"\nSecret #{i+1}:")
                    secret_data = secret_plist.get('v_Data')
                    if secret_data:
                        try:
                            inner_plist = plistlib.loads(secret_data)
                            print(f"  Decoded Plist Data: {inner_plist}")
                        except Exception:
                             print(f"  v_Data (bytes): {secret_data[:100]}...")
                    else:
                        print(f"  Full Plist: {secret_plist}")
            else:
                print("\n--- Process finished. No device secrets found. ---")

        except Exception as e:
            print(f"\n--- AN ERROR OCCURRED during secret retrieval ---")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting.")