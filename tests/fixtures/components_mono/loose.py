"""Top-level script outside any build-manifest component root."""

import os


def main() -> int:
    return len(os.listdir("."))
