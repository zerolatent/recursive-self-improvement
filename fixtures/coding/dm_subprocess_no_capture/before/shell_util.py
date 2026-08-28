"""Subprocess helper for running trusted, fixed-argument commands."""

import subprocess


def run_command(args: list[str]) -> str:
    """Run a command and return its captured stdout as text."""
    proc = subprocess.run(args, check=True)
    return proc.stdout
