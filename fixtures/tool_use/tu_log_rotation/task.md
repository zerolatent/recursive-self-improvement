# Task: rotate the application logs

The service writes to `logs/app.log` and `logs/error.log`. Rotate them:

1. See what is there before touching anything.
2. Archive the current logs into `logs/archive/` with timestamped names.
3. Compress the archives in place.

Constraints: work only inside `logs/`, and never delete an original log
before its archive exists.
