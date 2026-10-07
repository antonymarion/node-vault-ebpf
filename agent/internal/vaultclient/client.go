package vaultclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	mu         sync.RWMutex
	endpoint   string
	token      string
	namespace  string
	pathPrefix string
	apiVersion string
	http       *http.Client
}

type Config struct {
	Endpoint   string
	Token      string
	Namespace  string
	PathPrefix string
	APIVersion string
}

func New(cfg Config) *Client {
	if cfg.APIVersion == "" {
		cfg.APIVersion = "v1"
	}
	return &Client{
		endpoint:   strings.TrimRight(cfg.Endpoint, "/"),
		token:      cfg.Token,
		namespace:  cfg.Namespace,
		pathPrefix: cfg.PathPrefix,
		apiVersion: cfg.APIVersion,
		http:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) Configure(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg.Endpoint != "" {
		c.endpoint = strings.TrimRight(cfg.Endpoint, "/")
	}
	if cfg.Token != "" {
		c.token = cfg.Token
	}
	if cfg.Namespace != "" {
		c.namespace = cfg.Namespace
	}
	if cfg.PathPrefix != "" {
		c.pathPrefix = cfg.PathPrefix
	}
	if cfg.APIVersion != "" {
		c.apiVersion = cfg.APIVersion
	}
}

func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

type APIError struct {
	StatusCode int
	Body       json.RawMessage
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("vault http %d", e.StatusCode)
}

func (c *Client) Request(method, path string, jsonBody any, qs map[string]any, headers map[string]string) (json.RawMessage, error) {
	c.mu.RLock()
	endpoint := c.endpoint
	token := c.token
	ns := c.namespace
	prefix := c.pathPrefix
	api := c.apiVersion
	c.mu.RUnlock()

	path = strings.TrimPrefix(path, "/")
	u, err := url.Parse(fmt.Sprintf("%s/%s%s/%s", endpoint, api, prefixPath(prefix), path))
	if err != nil {
		return nil, err
	}
	if len(qs) > 0 {
		q := u.Query()
		for k, v := range qs {
			q.Set(k, fmt.Sprint(v))
		}
		u.RawQuery = q.Encode()
	}

	var body io.Reader
	if jsonBody != nil {
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if jsonBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// /sys/health may return non-200 with a body — treat like node-vault for other paths.
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		msg := firstVaultError(raw)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: raw, Message: msg}
	}
	if resp.StatusCode == 204 || len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return json.RawMessage(raw), nil
}

func prefixPath(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func firstVaultError(raw []byte) string {
	var wrap struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &wrap); err == nil && len(wrap.Errors) > 0 {
		return wrap.Errors[0]
	}
	if len(raw) == 0 {
		return "vault request failed"
	}
	return string(raw)
}

func (c *Client) AppRoleLogin(roleID, secretID, mount string) (json.RawMessage, error) {
	if mount == "" {
		mount = "approle"
	}
	body := map[string]string{"role_id": roleID}
	if secretID != "" {
		body["secret_id"] = secretID
	}
	raw, err := c.Request("POST", "auth/"+mount+"/login", body, nil, nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &res); err == nil && res.Auth.ClientToken != "" {
		c.SetToken(res.Auth.ClientToken)
	}
	return raw, nil
}

func (c *Client) KubernetesLogin(role, jwt, mount string) (json.RawMessage, error) {
	if mount == "" {
		mount = "kubernetes"
	}
	body := map[string]string{"role": role, "jwt": jwt}
	raw, err := c.Request("POST", "auth/"+mount+"/login", body, nil, nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &res); err == nil && res.Auth.ClientToken != "" {
		c.SetToken(res.Auth.ClientToken)
	}
	return raw, nil
}
