# Bug: run_command's return value is always None

`subprocess.run` is called without `capture_output=True` (or `text=True`), so `proc.stdout` is `None` rather than the command's output.
