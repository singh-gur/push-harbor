// webpush-go against the capture server. Prints one JSON line per case.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// headerClient adds custom headers: webpush-go has no option for them, only an HTTPClient hook.
type headerClient struct{ headers map[string]string }

func (c headerClient) Do(req *http.Request) (*http.Response, error) {
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

func main() {
	raw, _ := os.ReadFile("../subscription.json")
	var sub struct{ P256dh, Auth string }
	_ = json.Unmarshal(raw, &sub)
	priv, pub, _ := webpush.GenerateVAPIDKeys()
	lib := "webpush-go"
	if len(os.Args) > 1 {
		lib = os.Args[1] // "webpush-go" (defaults) or "webpush-go-rs2900"
	}
	for _, status := range []int{201, 404, 410, 413, 429} {
		size := 10
		if status == 201 {
			size = 2797
		}
		opts := &webpush.Options{
			Subscriber:      "survey@example.com",
			VAPIDPublicKey:  pub,
			VAPIDPrivateKey: priv,
			TTL:             60,
			VapidExpiration: time.Now().Add(time.Hour), // to check whether it is honoured
			HTTPClient:      headerClient{map[string]string{"Idempotency-Key": "idem-go"}},
		}
		if lib == "webpush-go-rs2900" {
			opts.RecordSize = 2900
		}
		target := &webpush.Subscription{
			Endpoint: fmt.Sprintf("http://127.0.0.1:8899/ep/%d?lib=%s", status, lib),
			Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
		}
		resp, err := webpush.SendNotification([]byte(strings.Repeat("x", size)), target, opts)
		out := map[string]any{"lib": lib, "status": status}
		if err != nil {
			out["outcome"] = "error: " + err.Error()
		} else {
			out["outcome"] = "returned *http.Response (no error)"
			out["statusCode"] = resp.StatusCode
			out["retryAfter"] = resp.Header.Get("Retry-After")
			resp.Body.Close()
		}
		line, _ := json.Marshal(out)
		fmt.Println(string(line))
	}
}
