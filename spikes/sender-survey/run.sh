#!/usr/bin/env bash
# PH-25: runs every library against the capture server. Needs node, go, uv, docker, openssl.
set -euo pipefail
cd "$(dirname "$0")"
rm -f captures.jsonl results.jsonl
node keys.mjs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls-key.pem -out tls-cert.pem \
  -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 2>/dev/null
TLS_KEY=tls-key.pem TLS_CERT=tls-cert.pem node capture.mjs >/dev/null & CAP=$!
trap 'kill $CAP' EXIT
sleep 1
php() { docker run --rm --network host -v "$PWD":/app:Z -w /app/php composer:2 php -d error_reporting="E_ALL & ~E_NOTICE & ~E_USER_NOTICE" send.php "$@"; }
{
  NODE_TLS_REJECT_UNAUTHORIZED=0 node --no-warnings node/send.mjs
  uv run -q --with pywebpush==2.5.0 python python/send.py
  (cd go && go run . webpush-go && go run . webpush-go-rs2900)
  php web-push-php
  php web-push-php-nopad
} > results.jsonl
echo "results: $(wc -l < results.jsonl) cases, captures: $(wc -l < captures.jsonl) requests"
