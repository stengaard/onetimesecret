// Package onetimesecret provides an API client for onetimesecret.com
package onetimesecret

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const baseAPI = "https://onetimesecret.com/api/v1"

// Client is how we interact with onetimesecret.com
type Client struct {
	Username, APIToken string
}

// Option defines specific optional features of managing secrets
type Option func(params url.Values)

func apply(data url.Values, opts ...Option) {
	for _, opt := range opts {
		opt(data)
	}
}

// WithTTL makes a secret expire after n seconds.
func WithTTL(d time.Duration) Option {
	return func(params url.Values) {
		params.Set("ttl", strconv.Itoa(int(d.Seconds())))
	}
}

// WithPassphrase sets a passphrase on the secret.
func WithPassphrase(phrase string) Option {
	return func(params url.Values) {
		params.Set("passphrase", phrase)
	}
}

// WithRecipient generates a friendly email containing the secret link (NOT the secret itself).
// Username and APItoken need to be valid on the client for this to work.
func WithRecipient(toEmail string) Option {
	return func(params url.Values) {
		params.Set("recipient", toEmail)
	}
}

// CreateSecret creates a secret with value and returns the metadata
func (c *Client) CreateSecret(value string, opts ...Option) (Metadata, error) {
	m := Metadata{}
	data := url.Values{
		"secret": {value},
	}
	apply(data, opts...)
	err := c.Do("POST", "/share", data, &m)
	if err != nil {
		return Metadata{}, err
	}
	return m, nil
}

// GenerateSecret creates a secret in onetimesecret and gives you the metadata to share with consumers.
func (c *Client) GenerateSecret(opts ...Option) (GeneratedSecret, error) {
	s := GeneratedSecret{}
	data := url.Values{}
	apply(data, opts...)
	err := c.Do("POST", "/generate", data, &s)
	if err != nil {
		return GeneratedSecret{}, err
	}
	return s, nil
}

// RetrieveSecret fetches a secret. It is equivalent to RetrieveSecretWithPassphrase(secretKey, "")
func (c *Client) RetrieveSecret(secretKey string) (secretValue string, err error) {
	return c.RetrieveSecretWithPassphrase(secretKey, "")
}

// RetrieveSecretWithPassphrase fetches the secret value from that is encrypted with a password.
// If passphrase is the empty string it is ignored.
func (c *Client) RetrieveSecretWithPassphrase(secretKey, passphrase string) (secretValue string, err error) {
	data := url.Values{}
	s := GeneratedSecret{}
	if passphrase != "" {
		data.Set("passphrase", passphrase)
	}
	err = c.Do("POST", "/secret/"+secretKey, data, &s)
	if err != nil {
		return "", err
	}
	return s.Value, nil

}

// RetrieveMetadata gets metadata about secret
func (c *Client) RetrieveMetadata(metadataKey string) (Metadata, error) {
	m := Metadata{}
	err := c.Do("POST", "/private/"+metadataKey, nil, &m)
	if err != nil {
		return Metadata{}, err
	}
	return m, nil
}

// RetrievesRecentMetadata fetches a list of recent metadata. c must containt Username and APIToken.
// The secret key is not present on any of the returned metadata.
// This endpoint is documented, but does not seem to work as there is path collision with the RetrieveMetadata endpoint.
func (c *Client) retrieveRecentMetadata() ([]Metadata, error) {
	m := []Metadata{}
	err := c.Do("POST", "/private/recent", nil, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Used in testing
var (
	reqCB  func(req *http.Request)
	respCB func(resp *http.Response)
)

// Do performs the actual API interaction
func (c *Client) Do(method, path string, params url.Values, out interface{}) error {
	req, err := http.NewRequest(method, baseAPI+path, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}

	if c.Username != "" && c.APIToken != "" {
		req.SetBasicAuth(c.Username, c.APIToken)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-onetimesecret/0.1")

	if reqCB != nil {
		reqCB(req)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if respCB != nil {
		respCB(resp)
	}

	if resp.StatusCode >= 400 {
		apiErr := APIError{}
		err = json.NewDecoder(resp.Body).Decode(&apiErr)
		if err != nil {
			return err
		}
		return apiErr
	}

	if out == nil {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(out)

}

// Timestamp represent time as it comes out of the onetimesecret API
type Timestamp int

// Time converts t into a time.Time
func (t *Timestamp) Time() time.Time {
	return time.Unix(int64(*t), 0)
}

// String makes Timestamp a fmt.Stringer
func (t *Timestamp) String() string {
	return t.Time().String()
}

// GeneratedSecret is a secret value and metadata about it.
type GeneratedSecret struct {
	Metadata
	Value string `json:"value"`
}

// Metadata contains data about a secret, but not the value itself.
type Metadata struct {
	CustomerID string `json:"custid"`

	//the unique key for the metadata. DO NOT share this.
	MetadataKey string `json:"metadata_key"`

	// the unique key for the secret you create. This is key that you can share.
	SecretKey string `json:"secret_key"`

	// List of email addresses. We will send a friendly email containing the secret link (NOT the secret itself).
	Recipient []string `json:"recipient"`

	// If a passphrase was provided when the secret was created, this will be true. Otherwise false, obviously.
	PassphraseRequired bool `json:"passphrase_required"`

	// The time-to-live (in seconds) that was specified (i.e. not the time remaining)
	TTL int `json:"ttl"`

	// The remaining time (in seconds) that the metadata has left to live.
	MetatdataTTL int `json:"metadata_ttl"`

	// The remaining time (in seconds) that the secret has left to live
	SecretTTL int `json:"secret_ttl"`

	// Time the secret was created (UTC)
	Created Timestamp `json:"created"`
	// When it was updated (UTC)
	Update Timestamp `json:"updated"`
	// When the secret was viewed by someone. Zero value means unviewed.
	Received Timestamp
}

// Deadline returns a time for when this secret expires
func (m Metadata) Deadline() time.Time {
	return m.Created.Time().Add(time.Duration(m.TTL) * time.Second)
}

// Status return "unread" if m.Received is 0 otherwise it returns "read"
func (m Metadata) Status() string {
	if m.Received == 0 {
		return "unread"
	}
	return "read"
}

// APIError is the format of error from the onetimesecret API
type APIError struct {
	Message string `json:"message"`
}

// Error makes APIError implement the error interface
func (e APIError) Error() string {
	return e.Message
}
