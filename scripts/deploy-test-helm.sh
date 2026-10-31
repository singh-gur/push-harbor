#!/usr/bin/env bash
# Smoke test of deploy/helm/pushharbor in a local kind cluster: PostgreSQL in the cluster, two
# relay replicas from the image built from this tree, the conformance suite against one pod and
# the multi-instance test across both, then the log check over both pods' logs.
# Needs docker, kind, kubectl, helm. The fake FCM runs in the test process on the host.
set -euo pipefail
cluster=ph-helm-test
secrets=$PWD/target/conformance-secrets.txt
kind get clusters 2>/dev/null | grep -qx $cluster || kind create cluster --name $cluster --wait 120s >/dev/null
trap 'kill $(jobs -p) 2>/dev/null || true; [ -n "${KEEP_CLUSTER:-}" ] || kind delete cluster --name $cluster >/dev/null 2>&1' EXIT
kubectl config use-context kind-$cluster >/dev/null

docker build -q -t pushharbor-native:dev . >/dev/null
kind load docker-image pushharbor-native:dev --name $cluster >/dev/null
kubectl apply -f deploy/helm/test/postgres.yaml >/dev/null
kubectl rollout status deploy/postgres --timeout=180s >/dev/null

# Pods reach the host (fake FCM) through the kind network's gateway.
gateway=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' | tr ' ' '\n' | grep -m1 '\.')
fcm=http://$gateway:9790
sed "s#http://127.0.0.1:9790#$fcm#" crates/conformance/fixtures/service-account.json > target/helm-sa.json
kubectl delete secret pushharbor --ignore-not-found >/dev/null
kubectl create secret generic pushharbor --from-file=fcm-service-account.json=target/helm-sa.json \
  --from-literal=database-url=postgres://postgres:pushharbor@postgres:5432/pushharbor \
  --from-literal=admin-token=conformance-admin-token-not-a-secret-0123456789 >/dev/null

helm upgrade --install relay deploy/helm/pushharbor --wait --timeout 180s \
  --set origin=http://127.0.0.1:8080 --set image.repository=pushharbor-native --set image.tag=dev \
  --set image.pullPolicy=Never --set trustedProxies=0 \
  --set env.PUSHHARBOR_FCM_API_BASE=$fcm --set-string env.PUSHHARBOR_PROVIDER_TIMEOUT_SECS=5 \
  --set-string env.PUSHHARBOR_REQUEST_TIMEOUT_SECS=8 \
  --set env.PUSHHARBOR_LIMIT_GLOBAL=1000000/60 --set env.PUSHHARBOR_LIMIT_PER_IP=1000000/60 \
  --set env.PUSHHARBOR_LIMIT_PER_SENDER=10/60 --set env.PUSHHARBOR_LIMIT_PER_ENDPOINT=5/60 \
  --set env.PUSHHARBOR_LIMIT_REGISTRATIONS_PER_IP=1000000/3600 \
  --set env.PUSHHARBOR_LIMIT_CHALLENGES_PER_TARGET=5/3600 >/dev/null

pods=($(kubectl get pods -l app.kubernetes.io/instance=relay -o name))
[ ${#pods[@]} -eq 2 ] || { echo "expected 2 relay pods, got ${#pods[@]}"; exit 1; }
kubectl port-forward "${pods[0]}" 8080:8080 >/dev/null 2>&1 &
kubectl port-forward "${pods[1]}" 8081:8080 >/dev/null 2>&1 &
kubectl port-forward svc/relay 9090:9090 >/dev/null 2>&1 &
for port in 8080 8081; do
  for _ in $(seq 60); do curl -sf http://127.0.0.1:$port/v1/health >/dev/null && break; sleep 0.5; done
done

rm -f "$secrets"
export FAKE_FCM_LISTEN=0.0.0.0:9790 CONFORMANCE_SECRETS=$secrets
RELAY_URL=http://127.0.0.1:8080 RELAY_REQUEST_TIMEOUT_SECS=8 \
  cargo test -q -p pushharbor-conformance --test conformance
RELAY_URL=http://127.0.0.1:8080 RELAY_URL_2=http://127.0.0.1:8081 \
  cargo test -q -p pushharbor-conformance --test multi_instance
curl -sf http://127.0.0.1:9090/metrics | grep -c pushharbor_requests_total | sed 's/^/metric series: /'
log=$(mktemp)
for pod in "${pods[@]}"; do kubectl logs "$pod" >> "$log"; done
RELAY_LOG=$log cargo test -q -p pushharbor-conformance --test logs
