# findmy/__main__.py
"""usage: python -m findmy"""  # noqa: D400, D415

from __future__ import annotations

import argparse
import asyncio # Add asyncio
import json
import logging
import os # Add os
import sys # Add sys
from importlib.metadata import version
from pathlib import Path

# --- Keep existing imports ---
from .plist import list_accessories

from .keychain_cli import add_keychain_parser # Import the arg parser setup

# --- ADD setup_logging ---
def setup_logging(verbosity: int):
    """Configure logging based on verbosity level."""
    # Default level is WARNING if verbosity is 0
    log_level = logging.WARNING
    if verbosity >= 2:
        log_level = logging.DEBUG
    elif verbosity == 1:
        log_level = logging.INFO # Set INFO for -v

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        # Use StreamHandler; file logging is handled within account/keychain if needed
        handlers=[logging.StreamHandler(sys.stdout)] # Log to stdout
    )
    # Adjust levels for noisy libraries if needed (optional)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    # Get the root logger used by basicConfig
    logger = logging.getLogger()
    logger.debug(f"Logging level set to {logging.getLevelName(log_level)}")


# --- Keep existing decrypt_all ---
def decrypt_all(out_dir: str | Path | None = None) -> None:
    """Decrypt all accessories and save them to the specified directory as JSON files."""

    def get_path(d: Path, acc) -> Path | None:  # noqa: ANN001
        if out_dir is None:
            return None
        # d is already a Path object from args
        d = d.resolve().absolute()
        d.mkdir(parents=True, exist_ok=True)
        # Sanitize identifier for filename (replace common problematic chars)
        safe_identifier = acc.identifier.replace(":", "_").replace("/", "_").replace("\\", "_")
        return d / f"{safe_identifier}.json"

    accs = list_accessories()
    json_accs = [a.to_json() for a in accs]

    print(json.dumps(json_accs, indent=2))

    if out_dir is not None:
        out_dir_path = Path(out_dir) # Ensure it's a Path object
        for i, acc in enumerate(accs):
            path = get_path(out_dir_path, acc)
            if path: # Should always be true if out_dir is not None
                 path.write_text(json.dumps(json_accs[i], indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="findmy", description="FindMy.py CLI tool")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase logging verbosity (-v for info, -vv for debug)."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('FindMy')}", # Use f-string for version format
    )
    # Remove --log-level, as it's replaced by -v/--verbose
    # parser.add_argument("--log-level", ...)

    subparsers = parser.add_subparsers(dest="command", title="commands")
    # Make command mandatory
    subparsers.required = True

    # --- Existing decrypt subparser ---
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt and print (in json) all the local FindMy accessories.",
        description="""
        This looks through the local FindMy accessory plist files,
        decrypts them using the system keychain, and prints the
        decrypted JSON representation of each accessory.

        eg
        ```
        [
            {
                "master_key": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                "skn": "e01ae426431867e92d512ae1cb6c9e5bbc20a2b7d1c677d7",
                # ...
            }
        ]
        ```

        You can chain the output with jq or similar tools.
        eg `python -m findmy decrypt | jq '.[] | select(.name == "my airtag")' > my_airtag.json`
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter # Keep formatting
    )
    decrypt_parser.add_argument(
        "--out-dir",
        type=Path, # Keep Path type
        default=None,
        help="Output directory for decrypted files. If not specified, files will not be saved to disk.",
    )
    # Link to sync function using lambda
    decrypt_parser.set_defaults(func=lambda args: decrypt_all(args.out_dir))

    # --- ADD THE NEW KEYCHAIN SUBPARSER ---
    add_keychain_parser(subparsers)


    args = parser.parse_args()

    # --- Call setup_logging AFTER parsing args ---
    setup_logging(args.verbose)
    # Get root logger after setup
    root_logger = logging.getLogger()


    # --- Modified execution logic ---
    if not args.command: # Should not happen if required=True
        parser.print_help()
        sys.exit(1)

    if hasattr(args, "func"):
        # Run the associated function
        if asyncio.iscoroutinefunction(args.func):
             try:
                  # Run the async function using asyncio.run
                  root_logger.debug(f"Running async command: {args.command}")
                  asyncio.run(args.func(args))
                  root_logger.debug(f"Async command {args.command} finished.")
             except KeyboardInterrupt:
                  root_logger.info("\\nCancelled by user.")
                  sys.exit(0) # Exit cleanly on Ctrl+C
             except Exception: # Catch any exception from the async func
                  # Log critical errors from async commands with traceback if debug
                  is_debug = root_logger.isEnabledFor(logging.DEBUG)
                  root_logger.critical(f"{args.command} command failed unexpectedly.", exc_info=is_debug)
                  sys.exit(1) # Exit with error code
        else:
             try:
                 # Run sync functions directly
                 root_logger.debug(f"Running sync command: {args.command}")
                 args.func(args)
                 root_logger.debug(f"Sync command {args.command} finished.")
             except KeyboardInterrupt:
                  root_logger.info("\\nCancelled by user.")
                  sys.exit(0)
             except Exception: # Catch any exception from the sync func
                  is_debug = root_logger.isEnabledFor(logging.DEBUG)
                  root_logger.critical(f"{args.command} command failed unexpectedly.", exc_info=is_debug)
                  sys.exit(1)
    else:
        # Fallback if a command is somehow added without a function
        root_logger.error(f"No function associated with command: {args.command}")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()