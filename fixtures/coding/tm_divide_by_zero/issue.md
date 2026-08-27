# Bug: dividing by zero silently returns 0.0

Callers need to know a zero denominator is their own bug. `safe_divide` currently swallows it and returns 0.0 instead of raising.
