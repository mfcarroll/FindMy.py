# findmy/keychain.py
"""Command-line logic for iCloud Keychain interaction (vouching and secret fetching)."""

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from typing import Any, Optional, cast

from findmy.reports.account import AsyncAppleAccount, LoginState
from findmy.reports.anisette import get_provider_from_mapping
from findmy.keychain.client import KeychainClient, KeychainClientState
from findmy.reports.state import AnisetteMapping
from findmy.util.files import read_data_json, save_and_return_json
# Necessary for handling bytes/Data in JSON output

logger = logging.getLogger(__name__)

# --- 2FA Helper (Uses AsyncAppleAccount methods directly) ---
async def handle_2fa(acc: AsyncAppleAccount) -> LoginState:
    """Handles the interactive 2FA process using account methods."""
    methods = await acc.get_2fa_methods()
    if not methods:
        logger.error("No 2FA methods found, but 2FA is required.")
        return acc.login_state

    # --- Simple Method Selection ---
    # More robust selection logic from test_keychain.py or __main__.py can be used here
    print("Select a 2FA method:")
    for i, method in enumerate(methods):
        # Assuming methods have a suitable __str__ or display name method
        print(f"  {i}: {method}") # Use method's string representation

    try:
        choice_str = input(f"Enter choice (0-{len(methods)-1}): ").strip()
        choice = int(choice_str)
        if not 0 <= choice < len(methods):
            raise ValueError("Invalid choice")
        method = methods[choice]

        logger.info(f"Requesting code via: {method}")
        await method.request() # Request code delivery

        code = input(f"Enter code sent to {method}: ").strip()
        if not code:
             raise ValueError("Empty code entered")

        logger.info("Submitting 2FA code...")
        new_state = await method.submit(code)
        return new_state

    except (ValueError, EOFError, KeyboardInterrupt):
        logger.error("\\nInvalid input or 2FA cancelled.")
        return acc.login_state # Return current (failed) state
# --- End 2FA Helper ---

async def run_keychain_flow(args: argparse.Namespace):
    """Orchestrates login, vouching, and fetching keychain secrets."""
    logger.info("Starting keychain fetch process...")
    acc: Optional[AsyncAppleAccount] = None # Define acc upfront for finally block

    # --- 1. State Loading ---
    state_file = args.state_file
    initial_acc_state = None
    initial_kc_state = None
    full_state = {}
    if state_file and os.path.exists(state_file):
        logger.info(f"Loading state from {state_file}")
        try:
            full_state = read_data_json(state_file) # Load entire state dict
            initial_acc_state = full_state.get('account')
            initial_kc_state = full_state.get('keychain')
            logger.debug("Loaded state successfully.")
        except Exception as e:
            logger.warning(f"Could not load state file {state_file}: {e}. Starting fresh.")
            initial_acc_state = None
            initial_kc_state = None # Ensure it's None if loading fails
    else:
         logger.info("No state file found or specified. Starting fresh.")

    # --- 2. Anisette & Account Setup ---
    try:
        # Determine anisette mapping (load from state or default to local)
        anisette_mapping = initial_acc_state.get('anisette') if initial_acc_state else {"provider_id": "local"}
        anisette = get_provider_from_mapping(initial_acc_state.get('anisette', {})) if initial_acc_state else get_provider_from_mapping(cast(AnisetteMapping, {"provider_id": "local"}))
        acc = AsyncAppleAccount(anisette=anisette, state_info=initial_acc_state)

        # --- 3. Login / Resume Session ---
        if acc.login_state < LoginState.LOGGED_IN: # Check if NOT logged in
            logger.info("Not logged in or session expired, attempting login...")
            try:
                # Determine Apple ID (args > state > prompt)
                apple_id = args.apple_id or (acc._username) or input("Enter Apple ID: ")
                # Determine Password (args > state [only if needed] > prompt)
                password_needed = not acc._password or acc.login_state == LoginState.LOGGED_OUT
                password = args.password if args.password else (acc._password if not password_needed else getpass.getpass("Enter Password: "))
                if not password: raise ValueError("Password required")
                if not apple_id: raise ValueError("Apple ID required")

            except (EOFError, KeyboardInterrupt, ValueError) as e:
                logger.error(f"\\nLogin input error or cancelled: {e}")
                if acc: await acc.close() # Close if initialized
                return

            logger.info(f"Logging in to {apple_id}...")
            state = await acc.login(apple_id, password)

            if state == LoginState.REQUIRE_2FA:
                logger.info("2FA required.")
                state = await handle_2fa(acc) # Use helper

            if state != LoginState.LOGGED_IN:
                logger.error(f"Login failed. Final state: {state.name}")
                if acc: await acc.close()
                return
            logger.info("Login successful.")
        else:
            logger.info(f"Resuming logged-in session for {acc.account_name}.")
            # Sanity check essential data for keychain operations
            if not acc._login_state_data.get("dsid") or not acc._login_state_data.get("adsid"):
                 logger.error("Resumed session state is missing dsid or adsid required for keychain. Please login again.")
                 if acc: await acc.close()
                 return


        # --- 4. Initialize KeychainClient ---
        # Ensure initial_kc_state structure if loaded, otherwise create empty
        if not isinstance(initial_kc_state, dict):
             logger.info("Initializing empty keychain state.")
             current_kc_state: KeychainClientState = {
                 "dsid": acc._login_state_data.get("dsid", ""),
                 "adsid": acc._login_state_data.get("adsid", ""),
                 "host": "", # Not strictly needed for vouching
                 "state_token": None,
                 "state": {},
                 "user_identity": None,
                 "keystore": {},
                 "keychain_items": {},
                 "sync_tokens": {},
             }
        else:
             # Validate/Ensure required top-level keys exist if loading state
             initial_kc_state.setdefault("dsid", acc._login_state_data.get("dsid", ""))
             initial_kc_state.setdefault("adsid", acc._login_state_data.get("adsid", ""))
             initial_kc_state.setdefault("host", "")
             initial_kc_state.setdefault("state_token", None)
             initial_kc_state.setdefault("state", {})
             initial_kc_state.setdefault("user_identity", None) # Will be loaded/recreated
             initial_kc_state.setdefault("keystore", {})
             initial_kc_state.setdefault("keychain_items", {})
             current_kc_state = cast(KeychainClientState, initial_kc_state)


        # Pass the prepared state dict to KeychainClient
        kc_client = KeychainClient(initial_state=current_kc_state, anisette_provider=anisette, account=acc)

        # --- 5. Join via Vouching (if necessary) ---
        identity = await kc_client.ensure_user_identity()
        # It's crucial to sync *before* checking inclusion status
        logger.info("Syncing keychain trust state...")
        await kc_client.sync_trust()

        # Check inclusion *after* syncing
        if identity.identifier not in identity.current_state.includeds:
            logger.info("Not currently in keychain circle. Need voucher to join.")
            try:
                voucher_b64 = input("Paste the base64 encoded voucher from sponsor device: ").strip()
                if not voucher_b64: raise ValueError("Empty voucher")
            except (EOFError, KeyboardInterrupt, ValueError):
                logger.error("\\nInvalid voucher input or cancelled.")
                if acc: await acc.close()
                return

            try:
                 logger.info("Attempting to join circle with provided voucher...")
                 await kc_client.join_with_voucher(voucher_b64)
                 logger.info("Successfully joined the keychain circle via voucher.")
            except Exception as e:
                 logger.error(f"Failed to join keychain circle: {e}", exc_info=True)
                 if acc: await acc.close()
                 return
        else:
             logger.info("Already part of the keychain circle.")

        # --- 6. Fetch Device Secrets ---
        # NOTE: This relies on IES decryption and CloudKit record fetching being implemented
        logger.info("Attempting to fetch and decrypt Find My secrets...")
        try:
            secrets = await kc_client.get_device_secrets()
            logger.info(f"Successfully processed keychain. Found {len(secrets)} Find My secrets.")

            # --- 7. Save/Output Secrets ---
            if args.out_dir:
                 output_dir = os.path.abspath(args.out_dir)
                 os.makedirs(output_dir, exist_ok=True)
                 logger.info(f"Saving secrets to directory: {output_dir}")
                 saved_count = 0
                 for i, secret in enumerate(secrets):
                     # Use 'labl' (label) if present, otherwise UUID, for filename
                     label = secret.get('labl', secret.get('_uuid', f'unknown_{i}'))
                     # Sanitize label for filename (simple alphanumeric + underscore)
                     safe_label = "".join(c if c.isalnum() else "_" for c in label).strip('_') or f'secret_{i}'
                     filename = os.path.join(output_dir, f"{safe_label}.json")
                     try:
                          with open(filename, 'w', encoding='utf-8') as f:
                               # Custom default function for JSON serialization
                               def json_serializer(obj):
                                    if isinstance(obj, bytes):
                                         # Try decoding as UTF-8, fallback to repr
                                         try: return obj.decode('utf-8')
                                         except UnicodeDecodeError: return repr(obj)
                                    elif isinstance(obj, Data): # Handle plistlib.Data
                                         return repr(obj.data) # Represent the inner bytes
                                    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

                               json.dump(secret, f, indent=2, default=json_serializer, ensure_ascii=False)
                          logger.debug(f"Saved secret to {filename}")
                          saved_count += 1
                     except Exception as e:
                          logger.error(f"Failed to save secret '{label}' to {filename}: {e}")
                 logger.info(f"Successfully saved {saved_count} secrets.")
            else:
                 # Print to console if no output dir
                 print("\n--- Decrypted Find My Secrets ---")
                 def json_serializer(obj):
                      if isinstance(obj, bytes):
                           try: return obj.decode('utf-8')
                           except UnicodeDecodeError: return repr(obj)
                      elif isinstance(obj, Data): return repr(obj.data)
                      raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
                 print(json.dumps(secrets, indent=2, default=json_serializer, ensure_ascii=False))
                 print("--- End Secrets ---")

        except NotImplementedError as e:
             logger.critical(f"Could not complete fetching secrets due to missing implementation: {e}")
             logger.critical("This likely requires implementing IES decryption or CloudKit record fetching.")
        except Exception as e:
             # Log traceback for debugging other errors
             logger.error(f"Failed during secret fetching/decryption: {e}", exc_info=True)


        # --- 8. Save State ---
        if state_file:
            logger.info(f"Saving final state to {state_file}")
            try:
                # Combine account and keychain state
                final_state = {
                    'account': acc.to_json(), # Get serializable state from account
                    # Use the *current* state dict from the client object
                    'keychain': kc_client.state
                }
                save_and_return_json(final_state, state_file) # Use helper to save
                logger.debug("State saved successfully.")
            except Exception as e:
                logger.error(f"Failed to save state to {state_file}: {e}")

    except Exception as e:
         # Catch-all for unexpected errors during setup/login
         logger.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
    finally:
        # Ensure account resources are always closed
        if acc: # Check if acc was successfully initialized
            await acc.close()
            logger.debug("Account resources closed.")

# --- Argument Parser Setup ---
def add_keychain_parser(subparsers: argparse._SubParsersAction):
    """Adds the 'keychain' command parser."""
    parser_keychain = subparsers.add_parser(
        "keychain",
        help="Join iCloud Keychain via vouching and fetch/decrypt FindMy secrets.",
        description="Logs into an Apple account, prompts for a voucher if needed to join the keychain sync circle, then fetches and decrypts FindMy device secrets stored in iCloud Keychain. NOTE: Requires IES decryption and CloudKit record fetching to be fully implemented."
    )
    parser_keychain.add_argument("--apple-id", help="Apple ID (email address). If omitted, uses state file or prompts.")
    parser_keychain.add_argument("--password", help="Password. If omitted, uses state file (if needed) or prompts securely.")
    parser_keychain.add_argument("--state-file", default="findmy_state.json", help="Path to save/load login and keychain state (JSON format). Default: findmy_state.json")
    parser_keychain.add_argument("--out-dir", help="Directory to save decrypted secrets (JSON format). If omitted, secrets are printed to stdout.")
    # Verbosity argument will be handled by the main parser in __main__.py
    parser_keychain.set_defaults(func=run_keychain_flow) # Link to async function