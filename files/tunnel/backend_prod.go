//go:build !testnode && !testcp

package main

import (
	"flag"
	"fmt"
	"io"
)

// The production backend: the node's real control-plane client, JWKS cache and feed. The node holds exactly one secret, its own Ed25519 signing key
// (-node-key-file, mode 0600); the control plane holds the public half in TUNNEL_NODE_KEYS and a node that is taken over is revoked by removing its
// kid there. There is no shared secret to configure, and the control plane's address is the issuer the policy pins unless an operator points a
// staging node somewhere else on purpose.

func init() {
	theBackend = &backend{flags: prodFlags}
	defaultMetricsAddr = "127.0.0.1:9101"
	defaultOpenAIPrefixesURL = "https://openai.com/chatgpt-connectors.json"
}

func prodFlags(fs *flag.FlagSet, stdout io.Writer) func(*Config) error {
	controlURL := fs.String("control-url", envStr("TUNNEL_CONTROL_URL", policyData.Identity.Issuer), "the control plane (https://host[:port]): authorize, the feed and the published keys come from here only [TUNNEL_CONTROL_URL]")
	keyFile := fs.String("node-key-file", envStr("TUNNEL_NODE_KEY_FILE", ""), "this node's Ed25519 signing key (PKCS#8 PEM, mode 0600): the one credential this node has [TUNNEL_NODE_KEY_FILE]")
	kid := fs.String("node-kid", envStr("TUNNEL_NODE_KID", ""), "the kid of this node's public key in the control plane's TUNNEL_NODE_KEYS [TUNNEL_NODE_KID]")
	initKey := fs.Bool("node-key-init", false, "create the signing key at -node-key-file (never over an existing one), print the TUNNEL_NODE_KEYS entry that registers it, and exit")
	printKey := fs.Bool("node-key-print", false, "print the TUNNEL_NODE_KEYS entry of the key at -node-key-file and exit")
	return func(cfg *Config) error {
		if *keyFile == "" {
			return fmt.Errorf("the node needs its signing key: -node-key-file (create it once with -node-key-init)")
		}
		if (*initKey || *printKey) && (!reNodeID.MatchString(cfg.NodeID) || !reKID.MatchString(*kid)) {
			return fmt.Errorf("the TUNNEL_NODE_KEYS entry needs -node-id and -node-kid")
		}
		if *initKey {
			key, err := GenerateNodeKey(*keyFile)
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, NodeKeysEntry(cfg.NodeID, *kid, key))
			return errDone
		}
		key, err := LoadNodeKey(*keyFile)
		if err != nil {
			return err
		}
		if *printKey {
			fmt.Fprintln(stdout, NodeKeysEntry(cfg.NodeID, *kid, key))
			return errDone
		}
		control, err := NewHTTPControl(HTTPControlConfig{BaseURL: *controlURL, NodeID: cfg.NodeID, KID: *kid, Key: key, Version: version})
		if err != nil {
			return err
		}
		clk := newClock(cfg.Now, cfg.AfterFunc)
		health := &cpHealth{}
		jwks := NewJWKSCache(JWKSConfig{
			Fetch: control.FetchJWKS, Clock: clk, Log: cfg.Logger,
			Observe: func(ok bool) {
				if ok {
					health.good(clk.Now())
				} else {
					health.bad(clk.Now())
				}
			},
		})
		cfg.Keys, cfg.Control, cfg.Feed, cfg.Health = jwks, control, control, health
		cfg.Background = append(cfg.Background, jwks.Run)
		return nil
	}
}
