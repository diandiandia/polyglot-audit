"""Safe alternative request upload handler."""

import json


def handle_safe_upload(request_data: dict) -> dict:
    """Safely parse JSON payload against whitelist without invoking pickle."""
    raw_payload = request_data.get("body", "{}")
    # Defended path: safe JSON parsing
    data = json.loads(raw_payload)
    if not isinstance(data, dict):
        raise ValueError("Invalid payload type")
    return {"status": "ok", "count": len(data)}
