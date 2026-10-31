// PH-22 interop sender: webpush-go, configured only as docs/spec/send.md says.
// Usage: go-send <fixture.json>; prints one JSON line per case.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	webpush "github.com/SherClockHolmes/webpush-go"
)

type keyPair struct{ Public, Private string }

type fixture struct {
	Subject      string
	Vapid        keyPair
	Unbound      keyPair
	LimitedVapid keyPair `json:"limited_vapid"`
	Keys         struct{ P256dh, Auth string }
	Endpoints    struct{ Ok, Gone, Deleted, Limited string }
	AtCap        string `json:"at_cap"`
	OverCap      string `json:"over_cap"`
	Short        string
	IdemKey      string `json:"idempotency_key"`
}

// headerClient adds Idempotency-Key: webpush-go only exposes custom headers through HTTPClient.
type headerClient struct{ headers map[string]string }

func (c headerClient) Do(req *http.Request) (*http.Response, error) {
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		panic(err)
	}
	send := func(name, endpoint, payload string, vapid keyPair, headers map[string]string) (int, string) {
		opts := &webpush.Options{
			Subscriber:      f.Subject,
			VAPIDPublicKey:  vapid.Public,
			VAPIDPrivateKey: vapid.Private,
			TTL:             3600,
			RecordSize:      2900, // required: the default pads every body to 4096 B
		}
		if headers != nil {
			opts.HTTPClient = headerClient{headers}
		}
		sub := &webpush.Subscription{Endpoint: endpoint, Keys: webpush.Keys{P256dh: f.Keys.P256dh, Auth: f.Keys.Auth}}
		resp, err := webpush.SendNotification([]byte(payload), sub, opts)
		if err != nil {
			// With RecordSize 2900 the library itself refuses over-cap payloads.
			line, _ := json.Marshal(map[string]any{"case": name, "status": nil, "error": err.Error()})
			fmt.Println(string(line))
			return 0, ""
		}
		resp.Body.Close()
		var retryAfter any
		if v := resp.Header.Get("Retry-After"); v != "" {
			retryAfter = v
		}
		line, _ := json.Marshal(map[string]any{"case": name, "status": resp.StatusCode, "retry_after": retryAfter})
		fmt.Println(string(line))
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}
	idem := map[string]string{"Idempotency-Key": f.IdemKey}
	send("at_cap", f.Endpoints.Ok, f.AtCap, f.Vapid, nil)
	send("over_cap", f.Endpoints.Ok, f.OverCap, f.Vapid, nil)
	send("no_key", f.Endpoints.Ok, f.Short, f.Vapid, nil)
	send("idempotent_first", f.Endpoints.Ok, f.Short, f.Vapid, idem)
	send("idempotent_repeat", f.Endpoints.Ok, f.Short, f.Vapid, idem)
	send("unbound_key", f.Endpoints.Ok, f.Short, f.Unbound, nil)
	// No expired case: webpush-go ignores VapidExpiration (always now + 12 h).
	send("gone_first", f.Endpoints.Gone, f.Short, f.Vapid, nil)
	send("gone_second", f.Endpoints.Gone, f.Short, f.Vapid, nil)
	send("deleted", f.Endpoints.Deleted, f.Short, f.Vapid, nil)
	for i := 0; i < 10; i++ {
		status, retryAfter := send(fmt.Sprintf("limited_%d", i), f.Endpoints.Limited, f.Short, f.LimitedVapid, nil)
		if status != 201 {
			line, _ := json.Marshal(map[string]any{"case": "limited", "status": status, "retry_after": retryAfter})
			fmt.Println(string(line))
			break
		}
	}
}
