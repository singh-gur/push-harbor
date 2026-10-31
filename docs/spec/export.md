# Registration export and import

Operators can move a deployment between hosting options (Cloudflare Workers, native with SQLite,
native with PostgreSQL) without touching apps or servers. The relay exports its registrations
and the new deployment imports them; endpoint IDs, and therefore every subscription servers hold,
keep working.

## Format

JSON Lines (one JSON object per line, UTF-8, `\n`-terminated). The first line is a header, each
further line one registration:

```jsonl
{"format":"pushharbor-registrations","version":1,"origin":"https://push.example.com","exported_at":1793335000}
{"id":"7Qp2v0bZ3k8mYx1aR4tW9g","platform":"fcm","target":"dXl7S0lJ_3pWQ4m2rZ8yAb","key_id":"k7Gq2","sender_key":"BG4kV_wdOWn4UH9PnI0-IEaju8oyUbv6rQ-EhSAmQz8vDzBcrwu7u2lDsv0hx063ISllIUtYT-CZMONCW82SEUI","created_at":1793300000}
```

Header:

| Field | Meaning |
|---|---|
| `format` | Always `pushharbor-registrations`. |
| `version` | `1`. An importer MUST refuse versions it does not know. |
| `origin` | The exporting relay's origin. |
| `exported_at` | Unix time of the export. |

Registration:

| Field | Meaning |
|---|---|
| `id` | Endpoint ID (22 characters base64url). |
| `platform` | `fcm` (later also `apns`). |
| `target` | Provider target (FCM Firebase Installation ID). |
| `key_id` | The app's key ID, sent to the device as `s`. |
| `sender_key` | Bound VAPID public key, uncompressed P-256, base64url. |
| `created_at` | Unix time the endpoint was first issued. |

Importers MUST ignore unknown fields. Not exported: pending registrations, idempotency keys, rate
limit counters and provider access tokens; all are short-lived.

## Import rules

- Each line is validated like a registration (ID format, platform, target, key ID, key). The
  importer reports invalid lines and imports none of the file if any line is invalid.
- An existing registration with the same `id` is replaced, so importing the same file twice is
  harmless.
- The new deployment MUST serve the **same origin**: endpoint URLs contain it, and it is the
  VAPID audience. Move DNS (or the route) after the import.
- The new deployment MUST use the **same Firebase project**: FIDs belong to one project.
- Registrations created on the old deployment after the export are lost; freeze registrations
  (or export again just before switching) to avoid that.
- An import overwrites registrations with the same `id` with the file's state; changes made on
  the destination after the export (rekey, target rotation) are reverted for those IDs.

## Admin API

Every hosting option serves the same two endpoints, **only when an admin token is configured**
(`PUSHHARBOR_ADMIN_TOKEN`, at least 32 characters; on Workers a secret). Without it they answer
404; with a missing or wrong `Authorization: Bearer <token>`, 403.

| Request | Response |
|---|---|
| `GET /v1/admin/export` | 200, `Content-Type: application/x-ndjson`, the file above |
| `POST /v1/admin/import` (body: the file) | 200 `{"imported": n}`; 400 `{"error": "bad_request", "message": ..., "line": n}` with nothing imported |

The native server also has CLI subcommands that work on its database directly, with the same
environment as the server: `pushharbor-native export > file` and `pushharbor-native import
file` (`-` for stdin).

## Moving a deployment

1. Deploy the destination with the **same origin** (not yet receiving traffic, e.g. reached
   through another hostname or locally), the **same Firebase project** and an admin token.
2. Export from the source (admin API or `pushharbor-native export`) and import into the
   destination. Check the import's `imported` count against the export's line count minus 1.
3. Point the origin's DNS (or route) at the destination.
4. Export from the source once more and import it, to catch registrations made during the
   switch. Then retire the source and delete the export files.

On the Workers free plan (10 ms CPU per request) split a large import into several files, each
with the header line and a few hundred registrations; importing is an upsert, so the parts can
be sent in any order or again.

## Handling

An export contains every endpoint ID, which are capabilities, and every device's provider
target. Store and transfer it like a credential and delete it after the import. Keep the admin
token unset when no migration is in progress.
