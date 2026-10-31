<?php
// PH-22 interop sender: web-push-php, configured only as docs/spec/send.md says.
// Usage: php send.php <fixture.json>; prints one JSON line per case.
// No Idempotency-Key cases (no option for custom headers) and no expired case (no expiry option).
require __DIR__.'/vendor/autoload.php';

use Minishlink\WebPush\Subscription;
use Minishlink\WebPush\WebPush;

$f = json_decode(file_get_contents($argv[1]), true);

function client(array $f, array $vapid): WebPush
{
    $webPush = new WebPush(['VAPID' => [
        'subject' => $f['subject'],
        'publicKey' => $vapid['public'],
        'privateKey' => $vapid['private'],
    ]], ['TTL' => 3600]);
    $webPush->setAutomaticPadding(false); // required: default padding exceeds the 2,900 B cap
    return $webPush;
}

function send(array $f, string $case, string $endpoint, string $payload, ?array $vapid = null): array
{
    $report = client($f, $vapid ?? $f['vapid'])->sendOneNotification(Subscription::create([
        'endpoint' => $endpoint,
        'publicKey' => $f['keys']['p256dh'],
        'authToken' => $f['keys']['auth'],
        'contentEncoding' => 'aes128gcm',
    ]), $payload);
    $response = $report->getResponse();
    if ($response === null) {
        throw new RuntimeException("$case: no response: ".$report->getReason());
    }
    $retryAfter = $response->getHeaderLine('Retry-After') ?: null;
    echo json_encode(['case' => $case, 'status' => $response->getStatusCode(), 'retry_after' => $retryAfter])."\n";
    return [$response->getStatusCode(), $retryAfter];
}

$ok = $f['endpoints']['ok'];
send($f, 'at_cap', $ok, $f['at_cap']);
send($f, 'over_cap', $ok, $f['over_cap']);
send($f, 'no_key', $ok, $f['short']);
send($f, 'unbound_key', $ok, $f['short'], $f['unbound']);
send($f, 'gone_first', $f['endpoints']['gone'], $f['short']);
send($f, 'gone_second', $f['endpoints']['gone'], $f['short']);
send($f, 'deleted', $f['endpoints']['deleted'], $f['short']);
for ($i = 0; $i < 10; $i++) {
    [$status, $retryAfter] = send($f, "limited_$i", $f['endpoints']['limited'], $f['short'], $f['limited_vapid']);
    if ($status !== 201) {
        echo json_encode(['case' => 'limited', 'status' => $status, 'retry_after' => $retryAfter])."\n";
        break;
    }
}
