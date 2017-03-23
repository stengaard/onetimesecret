package onetimesecret

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"testing"
	"time"
)

var (
	username = flag.String("ots.username", "", "The API user to auth as during tests")
	apikey   = flag.String("ots.apikey", "", "The API key to use during tests")
	email    = flag.String("ots.email", "", "Test that we receive an email with the secret link")
)

func TestAPICreateSecret(t *testing.T) {
	cleanup := withDebugOutput(t)
	defer cleanup()

	c := getAuthedClient(t)
	s, err := c.CreateSecret("abc123")
	t.Log(s)
	if err != nil {
		t.Fatalf("Could not create secret: %v", err)
	}
	expectUser := *username
	if expectUser == "" {
		// if username isn't set we've created the secret as anon
		expectUser = "anon"
	}
	if s.CustomerID != expectUser {
		t.Errorf("Bad owner: %q expected %q", s.CustomerID, expectUser)
	}
}

func TestWithTTL(t *testing.T) {
	data := url.Values{}
	fn := WithTTL(123 * time.Second)
	fn(data)
	if data.Get("ttl") != "123" {
		t.Fatalf("expected 123 TTL but found %s", data.Get("ttl"))
	}
}

func TestAPICreateSecretWithTTL(t *testing.T) {
	cleanup := withDebugOutput(t)
	defer cleanup()
	c := getAuthedClient(t)

	// Upstream seems to insists on minumum TTL of 14 days (336 hours)
	d := 14*24*time.Hour + 1*time.Minute

	s, err := c.CreateSecret("abc12asdfsdf3", WithTTL(d))
	if err != nil {
		t.Fatalf("could not create secret: %v", err)
	}

	if s.TTL != int(d.Seconds()) {
		t.Errorf("Expected TTL of %v but found %v", d, time.Duration(s.TTL)*time.Second)
		t.Logf("%#v", s)
	}

}

func TestAPICreateAndFetchSecret(t *testing.T) {
	c := getAuthedClient(t)
	gen, err := c.GenerateSecret()
	if err != nil {
		t.Fatalf("could not create secret: %v", err)
	}

	if gen.SecretTTL <= 0 || gen.MetatdataTTL <= 0 {
		t.Errorf("expected the ttls to be set on gen: %v", gen)
	}

	fetch, err := c.RetrieveSecret(gen.SecretKey)
	if err != nil {
		t.Fatalf("could not fetch secret: %v", err)
	}

	if fetch != gen.Value {
		t.Errorf("expected fetched (%q) and generated (%q) values to be equal", fetch, gen.Value)
	}
}

func TestAPICreateAndFetchSecretWithPassphrase(t *testing.T) {
	c := getAuthedClient(t)
	gen, err := c.GenerateSecret(WithPassphrase("verysecure"))
	if err != nil {
		t.Fatalf("could not create secret: %v", err)
	}

	if !gen.PassphraseRequired {
		t.Errorf("expected to passphrase_required be set on gen: %v", gen)
	}

	fetch, err := c.RetrieveSecretWithPassphrase(gen.SecretKey, "verysecure")
	if err != nil {
		t.Fatalf("could not fetch secret: %v", err)
	}

	if fetch != gen.Value {
		t.Errorf("expected fetched (%q) and generated (%q) values to be equal", fetch, gen.Value)
	}
}

func TestAPICreateAndFetchSecretWithWrongPassphrase(t *testing.T) {
	cleanup := withDebugOutput(t)
	defer cleanup()
	c := getAuthedClient(t)
	gen, err := c.GenerateSecret(WithPassphrase("verysecure"))
	if err != nil {
		t.Fatalf("could not create secret: %v", err)
	}

	if !gen.PassphraseRequired {
		t.Errorf("expected to passphrase_required be set on gen: %v", gen)
	}

	fetch, err := c.RetrieveSecretWithPassphrase(gen.SecretKey, "not very secure")
	if err == nil {
		t.Fatalf("could unexpectedly fetch secret: %v", fetch)
	}

	aerr, ok := err.(APIError)
	if !ok {
		t.Errorf("Expected an API error message, but got %T, %v", err, err)
	}

	if aerr.Message != "Unknown secret" {
		t.Errorf("unexpected error message: %v", aerr.Message)
	}
}

func TestAPICreateSecretUnauthed(t *testing.T) {
	c := Client{} // Zero value should be useful
	s, err := c.CreateSecret("abv123")
	if err != nil {
		t.Errorf("could not create secret: %v", err)
	}
	if s.CustomerID != "anon" {
		t.Fatalf("expected anon user but found %q", s.CustomerID)
	}
}

func TestGenerateSecretWithEmail(t *testing.T) {
	if *email == "" {
		t.Skip("no email specified")
	}

	cleanup := withDebugOutput(t)
	defer cleanup()
	c := getAuthedClient(t)
	s, err := c.GenerateSecret(WithRecipient(*email))
	if err != nil {
		t.Fatalf("could not generate link: %v", err)
	}
	if reflect.DeepEqual(s.Recipient, []string{*email}) {
		t.Errorf("expected recipient to be %q but found %q", *email, s.Recipient)
	}

}

// TestGenerateEndToEnd tests that we can create a secret, get it and then
// fetch the metadata about it and that it describes the time of viewing.
func TestGenerateEndToEnd(t *testing.T) {
	c := getAuthedClient(t)
	gen, err := c.GenerateSecret()
	if err != nil {
		t.Fatalf("could not create secret: %v", err)
	}
	s, err := c.RetrieveSecret(gen.SecretKey)
	if gen.Value != s {
		t.Errorf("expected same secret: %q %q", s, gen.Value)
	}

	m, err := c.RetrieveMetadata(gen.MetadataKey)
	if err != nil {
		t.Error("Could not fetch metadata", err)
	}

	if m.Received == 0 {
		t.Errorf("expected received value to have been set: %#v", m)
	}

}

func TestTimestamp(t *testing.T) {
	ts := Timestamp(1490224384)
	exp := "2017-03-22 23:13:04 +0000 UTC"
	if ts.Time().UTC().String() != exp {
		t.Errorf("expect %q but got %q", exp, ts.Time().UTC().String())
	}
}

func TestRecent(t *testing.T) {
	c := Client{}
	cleanup := withDebugOutput(t)
	defer cleanup()

	m, err := c.GenerateSecret()
	if err != nil {
		t.Fatalf("could not create secret %v", err)
	}

	ms, err := c.RetrieveRecentMetadata()
	if err != nil {
		t.Fatalf("could not fetch recent activity: %v", err)
	}

	if ms[0].MetadataKey != m.MetadataKey {
		t.Fatalf("Expected %s to be in %#v", m.MetadataKey, ms)
	}

}

func withDebugOutput(t *testing.T) func() {
	reqCB = func(req *http.Request) {
		outgoing, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			t.Fatalf("Could not dump outgoing request: %v", err)
		}
		t.Logf("Request:\n%s", string(outgoing))

	}
	respCB = func(resp *http.Response) {
		incoming, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Fatalf("Could not dump incoming response: %v", err)
		}
		t.Logf("Response:\n%s", string(incoming))
	}

	return func() {
		reqCB, respCB = nil, nil
	}
}

func getAuthedClient(t *testing.T) Client {
	if *username == "" || *apikey == "" {
		t.Log("No credentials given - expect failures and/or rate limits")
	}
	c := Client{
		Username: *username,
		APIToken: *apikey,
	}
	return c
}

func (t Timestamp) GoString() string {
	return fmt.Sprintf("%q", t.String())
}
