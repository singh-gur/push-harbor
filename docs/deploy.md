# Deploying a Pushharbor relay

One relay serves one published app: it holds that app's Firebase service account. Pick a hosting
option; all of them speak the same protocol ([docs/spec](spec/README.md)) and you can move
between them later without touching apps or servers ([export/import](spec/export.md)).

| Option | Storage | Instances | Good for |
|---|---|---|---|
| [Cloudflare Workers](#cloudflare-workers) | Durable Object (SQLite) | managed | lowest cost, no servers |
| [Docker Compose](#docker-compose) | SQLite on a volume | 1 | a single VPS |
| [Helm](#helm) | PostgreSQL | any | Kubernetes |
| [Cloud Run](#cloud-run) | Cloud SQL (PostgreSQL) | any, scales to zero | managed containers |

Every option needs:

- **An origin**: the public HTTPS URL of the relay, e.g. `https://push.example.com`. Endpoint
  URLs contain it and senders sign VAPID tokens for it, so it must stay the same for the life of
  the deployment. Use the default HTTPS port (web-push-php ignores other ports).
- **A Firebase service account** for your app's Firebase project (below). Keep the file secret.

## Firebase project

The relay delivers to Android through Firebase Cloud Messaging, with the Firebase project your
app is built with:

1. In the [Firebase console](https://console.firebase.google.com/), create a project (or use
   the app's existing one) and **add an Android app** with your app's package name. Download its
   `google-services.json` for the app build ([Expo module guide](expo.md)).
2. Cloud Messaging uses the FCM HTTP v1 API, which is enabled for new projects (Project settings
   → Cloud Messaging).
3. **Project settings → Service accounts → Generate new private key.** This JSON file is the
   relay's credential; it can send to every install of your app. Give it only to the relay.

One relay and one Firebase project per published app. Every self-hosted server of that app sends
through the same relay; they need no Firebase access.

Configuration is the same everywhere: `pushharbor-native --help` lists every variable
(`PUSHHARBOR_ORIGIN`, `PUSHHARBOR_LIMIT_<NAME>`, `PUSHHARBOR_TRUST_PROXY`, ...).

Check a deployment with `curl https://push.example.com/v1/health` → `{"status":"ok"}`.

## Container image

`ghcr.io/singh-gur/pushharbor-native:<version>` (also `:<major>.<minor>` and `:latest`), built
from the repository's `Dockerfile` and published on every release tag. It is distroless, runs as
UID 65532, listens on 8080 and keeps SQLite under `/data`.

## Cloudflare Workers

From `crates/worker` (needs Node.js, Rust with the `wasm32-unknown-unknown` target and
`cargo install worker-build@0.8.7`):

```sh
npm ci
npx wrangler login
npx wrangler secret put PUSHHARBOR_FCM_SERVICE_ACCOUNT < service-account.json
npx wrangler deploy --var PUSHHARBOR_ORIGIN:https://push.example.com
```

- Set `PUSHHARBOR_ORIGIN` in `wrangler.toml` `[vars]` instead of `--var` to keep it in version
  control, and add a [custom domain](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
  for it.
- The Durable Object class and its SQLite storage are created by the `[[migrations]]` block on
  the first deploy; later deploys keep the data.
- Limits: `--var PUSHHARBOR_LIMIT_PER_ENDPOINT:60/60` etc., or `[vars]`.
- Metrics (optional): enable Analytics Engine in the Cloudflare dashboard, then uncomment the
  `METRICS` binding in `wrangler.toml`. Request counts by route and status then go to the dataset
  `pushharbor_requests`; query them with the Analytics Engine SQL API. Deploys fail if the
  binding is present while Analytics Engine is disabled.
- Workers Logs are off on purpose (`observability.enabled = false`): they would record request
  URLs, and endpoint IDs are capabilities.
- Free plan: about 3 ms CPU per send, under the 10 ms limit; occasional cold starts can exceed
  it. The paid plan removes the concern.

## Docker Compose

`deploy/compose` runs the relay with SQLite on a named volume behind Caddy, which obtains the TLS
certificate and protects the relay from slow clients.

```sh
cd deploy/compose
mkdir -m 700 secrets && cp /path/to/service-account.json secrets/ && chmod 644 secrets/service-account.json
export PUSHHARBOR_DOMAIN=push.example.com FCM_SERVICE_ACCOUNT_FILE=./secrets/service-account.json
docker compose up -d
```

- The DNS name must point at the host and ports 80/443 must be reachable for Caddy's certificate.
- The service-account file must be readable by UID 65532 inside the container (hence `644`; the
  `700` directory keeps other users on the host out).
- Pin a version with `PUSHHARBOR_VERSION=0.1.0`. Upgrade: `docker compose pull && docker compose up -d`.
- Back up the `data` volume (SQLite) or use the export API.
- One instance only: rate limits live in its memory. For more, use PostgreSQL (Helm, Cloud Run).

## Helm

`deploy/helm/pushharbor` runs any number of replicas against PostgreSQL (bring your own: managed
or an operator). Rate limits, idempotency and pending registrations are shared through the
database.

```sh
kubectl create secret generic pushharbor \
  --from-file=fcm-service-account.json=service-account.json \
  --from-literal=database-url='postgres://user:password@postgres:5432/pushharbor'
helm install relay deploy/helm/pushharbor \
  --set origin=https://push.example.com \
  --set ingress.enabled=true --set ingress.host=push.example.com --set ingress.className=nginx
```

- Values: `replicaCount` (2), `trustedProxies` (1 for an ingress controller), `env` for limits,
  `ingress.tls`, `resources`, `podDisruptionBudget`. See `values.yaml`.
- Pods run as non-root with a read-only root filesystem; probes use `/v1/health`.
- Metrics: Prometheus `/metrics` on port 9090 of the Service (not routed by the Ingress).
- Migrations run on startup; concurrent replicas are safe.

## Cloud Run

`deploy/cloudrun/service.yaml` runs the image on Cloud Run with Cloud SQL for PostgreSQL. With
`gcloud` (replace `PROJECT`, `REGION`, `INSTANCE`):

```sh
gcloud sql instances create INSTANCE --database-version=POSTGRES_17 --region=REGION --tier=db-f1-micro
gcloud sql databases create pushharbor --instance=INSTANCE
gcloud sql users create pushharbor --instance=INSTANCE --password=PASSWORD

gcloud secrets create pushharbor-fcm-service-account --data-file=service-account.json
printf 'postgres://pushharbor:PASSWORD@localhost/pushharbor?host=/cloudsql/PROJECT:REGION:INSTANCE' \
  | gcloud secrets create pushharbor-database-url --data-file=-

# The service's runtime identity needs these roles:
gcloud projects add-iam-policy-binding PROJECT \
  --member=serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com --role=roles/cloudsql.client
gcloud projects add-iam-policy-binding PROJECT \
  --member=serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com --role=roles/secretmanager.secretAccessor

# Edit service.yaml (instance name, origin, image version), then:
gcloud run services replace deploy/cloudrun/service.yaml --region=REGION
gcloud run services add-iam-policy-binding pushharbor --region=REGION \
  --member=allUsers --role=roles/run.invoker
```

- Map the origin's domain to the service (Cloud Run domain mapping or a load balancer). Behind
  an external Application Load Balancer set `PUSHHARBOR_TRUST_PROXY` to 2.
- Cloud Run pulls public GHCR images directly; Google recommends an Artifact Registry remote
  repository in front of `ghcr.io`.
- This configuration is tested locally with the same container contract (no disk, secret file,
  Cloud SQL Unix socket), not on Google Cloud itself.

## Moving between options

Registrations move with an export/import: same origin, same Firebase project, then switch DNS.
The step-by-step procedure, the admin API and the native CLI are in
[docs/spec/export.md](spec/export.md#moving-a-deployment). Apps and servers notice nothing.

## Smoke tests

Each option has a recipe that starts it the way this guide does, with a fake FCM, and runs the
full conformance suite plus the no-secrets log check against it:

| Recipe | Runs |
|---|---|
| `just conformance-worker` | the Worker in `wrangler dev` |
| `just deploy-test-compose` | `deploy/compose` with Caddy; also checks SQLite survives a restart |
| `just deploy-test-helm` | the chart in a kind cluster, two replicas, in-cluster PostgreSQL |
| `just deploy-test-cloudrun` | the Cloud Run container contract locally, Cloud SQL socket included |
