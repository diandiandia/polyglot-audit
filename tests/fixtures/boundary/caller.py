"""Caller module demonstrating outgoing FFI frontier."""

import ctypes

lib = ctypes.CDLL("./libnative.so")


def dispatch_payload(user_input: str) -> None:
    # Frontier: source reaches boundary with native function
    payload_bytes = user_input.encode("utf-8")
    lib.execute_native_operation(payload_bytes)
