# pywebpush against the capture server. Prints one JSON line per case.
#   uv run --with pywebpush==2.5.0 --with py-vapid python python/send.py
import json
import pathlib

from py_vapid import Vapid
from pywebpush import WebPushException, webpush

sub = json.loads((pathlib.Path(__file__).parent.parent / "subscription.json").read_text())
vapid = Vapid()
vapid.generate_keys()
base = "http://127.0.0.1:8899/ep"
lib = "pywebpush"

for status in (201, 404, 410, 413, 429):
    payload = "x" * (2797 if status == 201 else 10)
    target = {"endpoint": f"{base}/{status}?lib={lib}", "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}}
    try:
        r = webpush(
            target,
            payload,
            vapid_private_key=vapid,
            vapid_claims={"sub": "mailto:survey@example.com"},
            headers={"Idempotency-Key": "idem-python"},
            ttl=60,
        )
        print(json.dumps({"lib": lib, "status": status, "outcome": "returned", "statusCode": r.status_code}))
    except WebPushException as e:
        print(json.dumps({"lib": lib, "status": status, "outcome": "throws WebPushException", "statusCode": e.status_code, "retryAfter": e.retry_after}))
