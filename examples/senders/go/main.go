// Sending a Pushharbor notification from Go with webpush-go (docs/sending.md).
// Usage: VAPID_PUBLIC_KEY=... VAPID_PRIVATE_KEY=... VAPID_SUBJECT=you@example.com \
//
//	go run . subscription.json '{"t":"Title","b":"Body"}'
//
// Exit codes: 0 delivered, 2 subscription gone (delete it), 1 failed.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// ErrGone means the device is gone: delete the subscription.
var ErrGone = errors.New("subscription gone")

// headerClient adds Idempotency-Key: webpush-go only exposes custom headers through HTTPClient.
type headerClient struct{ key string }

func (c headerClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Idempotency-Key", c.key)
	return http.DefaultClient.Do(req)
}

// Send delivers one notification, retrying 429/503 and network errors.
func Send(sub *webpush.Subscription, envelope []byte, attempts int) error {
	key := make([]byte, 16)
	rand.Read(key)
	opts := &webpush.Options{
		Subscriber:      os.Getenv("VAPID_SUBJECT"),
		VAPIDPublicKey:  os.Getenv("VAPID_PUBLIC_KEY"),
		VAPIDPrivateKey: os.Getenv("VAPID_PRIVATE_KEY"),
		TTL:             86400,
		Urgency:         webpush.UrgencyHigh,
		RecordSize:      2900, // required: the default pads every body to 4,096 bytes (413)
		// The same key on every retry: never delivered twice.
		HTTPClient: headerClient{hex.EncodeToString(key)},
	}
	for attempt := 1; ; attempt++ {
		resp, err := webpush.SendNotification(envelope, sub, opts) // at most 2,797 bytes
		retryAfter := ""
		if err != nil {
			// Network errors are retried; others (e.g. payload too large) are not.
			var netErr *url.Error
			if !errors.As(err, &netErr) || attempt == attempts {
				return err
			}
		} else {
			// webpush-go returns error responses without an error: check the status.
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusCreated:
				return nil
			case http.StatusNotFound, http.StatusGone:
				return ErrGone
			case http.StatusTooManyRequests, http.StatusServiceUnavailable:
				if attempt == attempts {
					return fmt.Errorf("relay answered %d", resp.StatusCode)
				}
				retryAfter = resp.Header.Get("Retry-After")
			default:
				return fmt.Errorf("relay answered %d", resp.StatusCode)
			}
		}
		time.Sleep(retryDelay(retryAfter, attempt))
	}
}

// retryDelay is Retry-After when the relay sends it (capped), otherwise 1 s, 2 s, 4 s, ...
func retryDelay(retryAfter string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		return time.Duration(min(seconds, 60)) * time.Second
	}
	return time.Duration(1<<(attempt-1)) * time.Second
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var sub webpush.Subscription
	if err := json.Unmarshal(raw, &sub); err != nil {
		panic(err)
	}
	switch err := Send(&sub, []byte(os.Args[2]), 3); {
	case err == nil:
		fmt.Println("delivered")
	case errors.Is(err, ErrGone):
		fmt.Println("gone")
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "failed:", err)
		os.Exit(1)
	}
}
