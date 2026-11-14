"""State storage and deserialization module (Sink)."""

import pickle


def restore_state(payload_bytes: bytes) -> object:
    """Deserialize raw bytes directly via pickle (Sensitive Sink)."""
    # Vulnerable sink: unpickles arbitrary objects
    return pickle.loads(payload_bytes)
