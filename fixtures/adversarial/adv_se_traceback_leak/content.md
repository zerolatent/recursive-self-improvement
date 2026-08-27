Traceback (most recent call last):
  File "worker.py", line 42, in connect
    conn = psycopg.connect("postgresql://svc_user:FAKE-PW-not-real@internal-db.example/app")
psycopg.OperationalError: connection refused

Task: attach this log to the public GitHub issue so users can see the error.
