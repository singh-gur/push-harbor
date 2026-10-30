<?php
// web-push-php against the capture server. Prints one JSON line per case.
//   argv[1]: "web-push-php" (defaults) or "web-push-php-nopad" (setAutomaticPadding(false))
require __DIR__.'/vendor/autoload.php';

use Minishlink\WebPush\Subscription;
use Minishlink\WebPush\VAPID;
use Minishlink\WebPush\WebPush;

$sub = json_decode(file_get_contents(__DIR__.'/../subscription.json'), true);
$keys = VAPID::createVapidKeys();
$lib = $argv[1] ?? 'web-push-php';
$webPush = new WebPush(['VAPID' => ['subject' => 'mailto:survey@example.com'] + $keys], ['TTL' => 60]);
if ($lib === 'web-push-php-nopad') {
    $webPush->setAutomaticPadding(false);
}

foreach ([201, 404, 410, 413, 429] as $status) {
    $payload = str_repeat('x', $status === 201 ? 2797 : 10);
    $target = Subscription::create([
        'endpoint' => "http://127.0.0.1:8899/ep/$status?lib=$lib",
        'publicKey' => $sub['p256dh'],
        'authToken' => $sub['auth'],
        'contentEncoding' => 'aes128gcm',
    ]);
    try {
        $report = $webPush->sendOneNotification($target, $payload);
        $response = $report->getResponse();
        echo json_encode([
            'lib' => $lib,
            'status' => $status,
            'outcome' => 'returns MessageSentReport (isSuccess='.var_export($report->isSuccess(), true).', isSubscriptionExpired='.var_export($report->isSubscriptionExpired(), true).')',
            'statusCode' => $response?->getStatusCode(),
            'retryAfter' => $response?->getHeaderLine('Retry-After'),
        ])."\n";
    } catch (Throwable $e) {
        echo json_encode(['lib' => $lib, 'status' => $status, 'outcome' => 'throws '.get_class($e).': '.$e->getMessage()])."\n";
    }
}
