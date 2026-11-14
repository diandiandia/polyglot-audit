"""Request upload handler module (Vulnerable taint entry point)."""

from app.storage.state import restore_state


def handle_upload(request_data: dict) -> dict:
    """Read request body and pass directly to restore_state without validation."""
    raw_payload = request_data.get("body", b"")
    # Untrusted user input flowing across file boundaries
    obj = restore_state(raw_payload)
    return {"status": "restored", "result": str(obj)}
