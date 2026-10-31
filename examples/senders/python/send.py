# Sending a Pushharbor notification from Python with pywebpush (docs/sending.md).
# Usage: VAPID_PRIVATE_KEY=... VAPID_SUBJECT=mailto:you@example.com \
#          uv run --with pywebpush==2.5.0 python send.py subscription.json '{"t":"Title","b":"Body"}'
# Exit codes: 0 delivered, 2 subscription gone (delete it), 1 failed.
import json
import os
import sys
import time
import uuid

from pywebpush import WebPushException, webpush


def send(subscription: dict, envelope: dict, attempts: int = 3) -> str:
    """Returns "delivered" or "gone"; raises when the relay or provider keeps failing."""
    payload = json.dumps(envelope, separators=(",", ":"))  # at most 2,797 bytes
    idempotency_key = str(uuid.uuid4())  # the same key on every retry: never delivered twice
    for attempt in range(1, attempts + 1):
        try:
            webpush(
                subscription,
                payload,
                vapid_private_key=os.environ["VAPID_PRIVATE_KEY"],
                # pywebpush fills in aud and a 12 h exp; it mutates the dict, so pass a new one.
                vapid_claims={"sub": os.environ["VAPID_SUBJECT"]},
                ttl=86400,  # required: pywebpush defaults to 0 (deliver now or drop)
                headers={"Idempotency-Key": idempotency_key, "Urgency": "high"},
            )
            return "delivered"
        except WebPushException as e:
            status = e.response.status_code if e.response is not None else None
            if status in (404, 410):
                return "gone"
            if status not in (None, 429, 503) or attempt == attempts:
                raise
            time.sleep(retry_delay(e.response.headers.get("Retry-After") if e.response is not None else None, attempt))
    raise AssertionError("unreachable")


def retry_delay(retry_after, attempt: int) -> float:
    """Retry-After when the relay sends it (capped), otherwise 1 s, 2 s, 4 s, ..."""
    try:
        return min(float(retry_after), 60.0) if retry_after else 2 ** (attempt - 1)
    except ValueError:
        return 2 ** (attempt - 1)


if __name__ == "__main__":
    subscription = json.load(open(sys.argv[1]))
    try:
        result = send(subscription, json.loads(sys.argv[2]))
    except WebPushException as e:
        print(f"failed: {e.response.status_code if e.response is not None else e}", file=sys.stderr)
        sys.exit(1)
    print(result)
    sys.exit(2 if result == "gone" else 0)
