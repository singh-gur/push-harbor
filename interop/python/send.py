# PH-22 interop sender: pywebpush, configured only as docs/spec/send.md says.
# Usage: uv run --with pywebpush==2.5.0 python send.py <fixture.json>; one JSON line per case.
import json
import sys
from urllib.parse import urlsplit

from py_vapid import Vapid02
from pywebpush import WebPushException, webpush

f = json.load(open(sys.argv[1]))


def send(name, endpoint, payload, vapid=None, headers=None, signed=False):
    status, retry_after = None, None
    try:
        r = webpush(
            {"endpoint": endpoint, "keys": f["keys"]},
            payload,
            # signed: Authorization is already in headers
            vapid_private_key=None if signed else (vapid or f["vapid"])["private"],
            vapid_claims=None if signed else {"sub": f["subject"]},
            headers=headers or {},
            ttl=3600,  # pywebpush defaults to 0 (deliver now or drop)
        )
        status = r.status_code
    except WebPushException as e:
        status = e.response.status_code
        retry_after = e.response.headers.get("Retry-After")
    print(json.dumps({"case": name, "status": status, "retry_after": retry_after}), flush=True)
    return status, retry_after


ok, idem = f["endpoints"]["ok"], {"Idempotency-Key": f["idempotency_key"]}
send("at_cap", ok, f["at_cap"])
send("over_cap", ok, f["over_cap"])
send("no_key", ok, f["short"])
send("idempotent_first", ok, f["short"], headers=idem)
send("idempotent_repeat", ok, f["short"], headers=idem)
send("unbound_key", ok, f["short"], vapid=f["unbound"])
# pywebpush replaces an expired `exp` with a fresh one; sign with py_vapid (its own dependency).
origin = "{0.scheme}://{0.netloc}".format(urlsplit(ok))
claims = {"sub": f["subject"], "aud": origin, "exp": f["expired_exp"]}
expired = Vapid02.from_string(f["vapid"]["private"]).sign(claims)["Authorization"]
send("expired", ok, f["short"], headers={"Authorization": expired}, signed=True)
send("gone_first", f["endpoints"]["gone"], f["short"])
send("gone_second", f["endpoints"]["gone"], f["short"])
send("deleted", f["endpoints"]["deleted"], f["short"])
for i in range(10):
    status, retry_after = send(f"limited_{i}", f["endpoints"]["limited"], f["short"], vapid=f["limited_vapid"])
    if status != 201:
        print(json.dumps({"case": "limited", "status": status, "retry_after": retry_after}))
        break
