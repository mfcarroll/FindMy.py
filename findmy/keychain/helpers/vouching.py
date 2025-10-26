# findmy/keychain/helpers/vouching.py
"""
High-level vouching helpers that call CloudKit/Cuttlefish via CloudKitManager.

This module depends on your generated `cloudkit_pb2` (imported as ckproto).
It tries likely Cuttlefish request/response message names but provides
clear fallback/adaptation comments. Adjust names if your cloudkit_pb2 differs.
"""
from __future__ import annotations

import logging
import base64
from typing import Optional, Tuple

from findmy.keychain import cloudkit_pb2 as ckproto
from findmy.keychain.helpers.encoded_peer import GeneratedPeer
from findmy.keychain.identity import KeychainUserIdentity

logger = logging.getLogger(__name__)


async def create_cuttlefish_peer_for_identity(
    identity: KeychainUserIdentity, stable_info: ckproto.PeerStableInfo
) -> ckproto.CuttlefishPeer:
    """
    Uses an existing KeychainUserIdentity to create a CuttlefishPeer protobuf populated
    with SignedInfo for stable_info and dynamic_info.

    Returns ckproto.CuttlefishPeer instance.
    """
    signed_stable = identity.sign_stable_info(stable_info)
    # identity.to_cuttlefish_peer will include permanent info and dynamic info.
    peer = identity.to_cuttlefish_peer(signed_stable, voucher=None)
    return peer


async def request_voucher_for_peer_via_cloudkit(
    cloudkit_manager, peer: ckproto.CuttlefishPeer
) -> Tuple[bytes, Optional[ckproto.SignedInfo]]:
    """
    Request a voucher for `peer` via the provided CloudKitManager.

    cloudkit_manager must be an instance of your CloudKitManager (the one returned by account._get_cloudkit_manager()).

    Returns a tuple (voucher_bytes, signed_info_proto). voucher_bytes is the raw
    response serialized bytes (which may be base64-encoded by callers); signed_info_proto
    is a parsed ckproto.SignedInfo instance (if parsing succeeded).

    IMPORTANT: The exact function name and request/response message types vary by proto version.
    We try common names and message classes. If your cloudkit_pb2 uses different
    identifiers, adapt the strings below.

    Likely function names seen in references:
      - "createVoucher"
      - "cuttlefishCreateVoucherRequest"
      - "CreateVoucher"
    """

    # Try likely request/response proto message classes.
    # Commonly there is a request type named "CuttlefishCreateVoucherRequest"
    # and response "CuttlefishCreateVoucherResponse" or a generic FunctionInvokeResponse wrapper.
    possible_req_names = [
        "CuttlefishCreateVoucherRequest",
        "CuttlefishCreateVoucherReq",
        "CreateVoucherRequest",
    ]
    possible_resp_names = [
        "CuttlefishCreateVoucherResponse",
        "CreateVoucherResponse",
        "FunctionInvokeResponse",
    ]

    # Build a minimal request proto if available
    req_proto = None
    for name in possible_req_names:
        if hasattr(ckproto, name):
            req_cls = getattr(ckproto, name)
            req_proto = req_cls()
            break

    if req_proto is None:
        # Fallback: some proto variants expect the peer to be passed directly as the "FunctionInvokeRequest" parameter.
        # In that case, we construct a generic FunctionInvokeRequest wrapper if available.
        if hasattr(ckproto, "FunctionInvokeRequest"):
            req_proto = ckproto.FunctionInvokeRequest()
            # Many FunctionInvokeRequest types have a 'name' and 'arguments' fields; we will set below.
        else:
            raise RuntimeError(
                "Could not find a CuttlefishCreateVoucherRequest type in ckproto. Please adapt vouching.py to your cloudkit_pb2 variant."
            )

    # Populate the request. The exact fields differ across proto versions.
    try:
        # If request has .peer field or .cuttlefish_peer, try to copy the peer
        if hasattr(req_proto, "peer"):
            req_proto.peer.CopyFrom(peer)  # type: ignore[attr-defined]
        elif hasattr(req_proto, "cuttlefish_peer"):
            req_proto.cuttlefish_peer.CopyFrom(peer)  # type: ignore[attr-defined]
        elif hasattr(req_proto, "argument"):  # single-arg style
            req_proto.argument = peer.SerializeToString()  # type: ignore[attr-defined]
        elif hasattr(req_proto, "parameters"):  # FunctionInvokeRequest style
            # pack the serialized peer as the parameters field
            req_proto.parameters = peer.SerializeToString()
        else:
            # Best-effort: try to set any repeated 'peers' or 'peers_to_create' field
            for field in ("peers", "peers_to_create", "peersToCreate"):
                if hasattr(req_proto, field):
                    getattr(req_proto, field).add().CopyFrom(peer)
                    break
    except Exception:
        # If we cannot set fields generically, raise and instruct developer to adapt
        raise RuntimeError(
            "Could not populate CuttlefishCreateVoucherRequest with peer. Adapt vouching helper to your ckproto fields."
        )

    # Now invoke via cloudkit_manager.invoke_cuttlefish.
    # The 'method' string must match Apple's internal function route; try a few candidates.
    possible_method_names = [
        "createVoucher",
        "cuttlefishCreateVoucherRequest",
        "CreateVoucher",
        "CuttlefishCreateVoucher",
    ]

    last_exc = None
    for method in possible_method_names:
        for resp_name in possible_resp_names:
            try:
                if hasattr(ckproto, resp_name):
                    response_class = getattr(ckproto, resp_name)
                else:
                    # Fallback to a generic FunctionInvokeResponse if present
                    response_class = getattr(ckproto, "FunctionInvokeResponse", None)
                if response_class is None:
                    response_class = getattr(ckproto, "FunctionInvokeResponse", None)
                logger.info(
                    f"Attempting Cuttlefish invoke method='{method}' resp='{response_class.__name__ if response_class else 'None'}'"
                )
                resp_proto = await cloudkit_manager.invoke_cuttlefish(
                    method, req_proto, response_class
                )
                # resp_proto may contain voucher bytes in different fields; try likely ones:
                if hasattr(resp_proto, "voucher") and getattr(resp_proto, "voucher"):
                    signed_info = ckproto.SignedInfo()
                    voucher_field = getattr(resp_proto, "voucher")
                    if isinstance(voucher_field, (bytes, bytearray)):
                        data_bytes = bytes(voucher_field)
                        try:
                            signed_info.ParseFromString(data_bytes)
                            return data_bytes, signed_info
                        except Exception:
                            return data_bytes, None
                    else:
                        # If voucher is a message, return its serialized bytes and the message
                        return (
                            voucher_field.SerializeToString(),
                            voucher_field,
                        )

                # sometimes the serialized result itself is the SignedInfo
                if hasattr(resp_proto, "signed_info") and getattr(
                    resp_proto, "signed_info"
                ):
                    si = resp_proto.signed_info
                    return si.SerializeToString(), si

                # Other variants may put bytes in serializedResult or payload fields
                val: bytes | bytearray | None = None  # ensure bound
                for candidate in (
                    "serialized_result",
                    "result",
                    "payload",
                    "signedVoucher",
                ):
                    if hasattr(resp_proto, candidate):
                        val = getattr(resp_proto, candidate)
                        if isinstance(val, (bytes, bytearray)) and val:
                            data_bytes = bytes(val)
                            si = ckproto.SignedInfo()
                            try:
                                si.ParseFromString(data_bytes)
                                return data_bytes, si
                            except Exception:
                                # return raw bytes if parsing fails
                                return data_bytes, None

                # If we reach here, invocation succeeded but voucher not found in expected places
                raise RuntimeError(
                    "Cuttlefish create-voucher response did not include voucher in expected fields."
                )

            except Exception as exc:
                last_exc = exc
                logger.debug(
                    f"Attempt with method '{method}' and resp '{resp_name}' failed: {exc}"
                )
                continue

    # If all attempts failed, raise the last exception with guidance
    raise RuntimeError(
        f"All attempts to invoke create-voucher failed. Last error: {last_exc}"
    )
