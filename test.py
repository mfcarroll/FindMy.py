from findmy.reports.anisette import LocalAnisetteProvider, LocalAnisetteMapping
from findmy.reports.state import State
from findmy.reports.account import AsyncAppleAccount
from findmy.keychain.identity import KeychainUserIdentity
from findmy.util.http import HttpSession
import asyncio

async def main():
    # Create anisette state (empty is fine — py-anisette will handle it)
    anisette_state = State(LocalAnisetteMapping(url="", data=None, path=None))
    anisette_provider = LocalAnisetteProvider(anisette_state)

    # Initialize Apple account
    account = AsyncAppleAccount(anisette_provider)

    # Load or generate identity
    identity = KeychainUserIdentity.load_from_disk()
    identity.bind_context(account, anisette_provider, HttpSession())

    print("Account UID:", account._uid)
    print("Anisette headers:", await anisette_provider.get_headers(account._uid, account._devid))

asyncio.run(main())
