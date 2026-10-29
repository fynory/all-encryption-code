package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// policy.json is the byte-identical copy of contracts/policy.json that `the contract generator's sync` writes (the Go module cannot read
// contracts/ at runtime). Every number, window and pattern of the node comes from it: nothing here types one again.
//
//go:embed policy.json
var policyJSON []byte

// Policy is the part of the ALL 2.0 policy table the node reads.
type Policy struct {
	Protocol struct {
		Version               int      `json:"version"`
		ALPN                  string   `json:"alpn"`
		LineMaxBytes          int      `json:"line_max_bytes"`
		OpenLineMaxBytes      int      `json:"open_line_max_bytes"`
		StatementLineMaxBytes int      `json:"statement_line_max_bytes"`
		JWTMaxBytes           int      `json:"jwt_max_bytes"`
		FirstLineTimeoutS     int      `json:"first_line_timeout_s"`
		AttachTimeoutS        int      `json:"attach_timeout_s"`
		HintMaxAddresses      int      `json:"hint_max_addresses"`
		ProofHTM              string   `json:"proof_htm"`
		ProofHTUPath          string   `json:"proof_htu_path"`
		SourceClasses         []string `json:"source_classes"`
		CloseReasons          []string `json:"close_reasons"`
		ErrorCodes            []string `json:"error_codes"`
	} `json:"protocol"`
	Timing struct {
		PingIntervalS          int `json:"ping_interval_s"`
		DeadPeerS              int `json:"dead_peer_s"`
		StreamIdleS            int `json:"stream_idle_s"`
		StreamMaxAgeS          int `json:"stream_max_age_s"`
		HalfCloseS             int `json:"half_close_s"`
		BackoffMinS            int `json:"backoff_min_s"`
		RenewBeforeValidUntilS int `json:"renew_before_valid_until_s"`
		BackoffMaxS            int `json:"backoff_max_s"`
		DrainQuietS            int `json:"drain_quiet_s"`
		FeedPollS              int `json:"feed_poll_s"`
		FeedApplyDeadlineS     int `json:"feed_apply_deadline_s"`
	} `json:"timing"`
	Authorization struct {
		SessionTTLS        int `json:"session_ttl_s"`
		ProofTTLS          int `json:"proof_ttl_s"`
		NodeSkewS          int `json:"node_skew_s"`
		NodeSkewMaxS       int `json:"node_skew_max_s"`
		AuthorizeMaxConcur int `json:"authorize_max_concurrent"`
		NodeAssertionTTLS  int `json:"node_assertion_ttl_s"`
		GracePaidS         int `json:"grace_paid_s"`
	} `json:"authorization"`
	Identity struct {
		Issuer         string `json:"issuer"`
		AudTunnel      string `json:"aud_tunnel"`
		AudNodeAssert  string `json:"aud_node_assertion"`
		FQDNRegex      string `json:"fqdn_regex"`
		FQDNMaxLength  int    `json:"fqdn_max_length"`
		LabelRegex     string `json:"label_regex"`
		DeviceIDRegex  string `json:"device_id_regex"`
		StreamIDRegex  string `json:"stream_id_regex"`
		AttachSecretRE string `json:"attach_secret_regex"`
		NonceRegex     string `json:"nonce_regex"`
		JTIRegex       string `json:"jti_regex"`
		KIDRegex       string `json:"kid_regex"`
	} `json:"identity"`
	JWKS struct {
		CacheS           int `json:"cache_s"`
		MaxKeys          int `json:"max_keys"`
		StaleFailClosedS int `json:"stale_fail_closed_s"`
	} `json:"jwks"`
	Enums struct {
		FeedEventType []string `json:"feed_event_type"`
	} `json:"enums"`
	NodeLimits struct {
		ClientHelloDeadlineS      int `json:"client_hello_deadline_s"`
		PerIPConcurrent           int `json:"per_ip_concurrent"`
		PerIPNewPerS              int `json:"per_ip_new_per_s"`
		IPv6PrefixBits            int `json:"ipv6_prefix_bits"`
		LabelStreamsMax           int `json:"label_streams_max"`
		LabelAnonSlice            int `json:"label_anon_slice"`
		LabelHintSlice            int `json:"label_hint_slice"`
		HintTTLS                  int `json:"hint_ttl_s"`
		GlobalStreamsMax          int `json:"global_streams_max"`
		OpenAIReservedPct         int `json:"openai_reserved_pct"`
		OpenAIPrefixRefreshS      int `json:"openai_prefix_refresh_s"`
		OpenAIPrefixMax           int `json:"openai_prefix_max"`
		OpenAIPrefixMinV4Bits     int `json:"openai_prefix_min_v4_bits"`
		OpenAIPrefixMinV6Bits     int `json:"openai_prefix_min_v6_bits"`
		OpenAIPrefixBodyMaxBytes  int `json:"openai_prefix_body_max_bytes"`
		OpenAIPerIPFactor         int `json:"openai_per_ip_factor"`
		DevicePerIPFactor         int `json:"device_per_ip_factor"`
		IPTableMax                int `json:"ip_table_max"`
		UnknownSNIPerIP           int `json:"unknown_sni_per_ip"`
		UnknownSNIWindowS         int `json:"unknown_sni_window_s"`
		UnknownSNIBanS            int `json:"unknown_sni_ban_s"`
		LabelNewPerS              int `json:"label_new_per_s"`
		LabelNewBurst             int `json:"label_new_burst"`
		HintAddressesPerLabel     int `json:"hint_addresses_per_label"`
		TCPKeepaliveS             int `json:"tcp_keepalive_s"`
		MaxUnauthenticatedControl int `json:"max_unauthenticated_control"`
	} `json:"node_limits"`
	Gated struct {
		BytesPerDay   int64 `json:"bytes_per_day"`
		StreamsPerDay int   `json:"streams_per_day"`
	} `json:"gated"`
}

// policyData is the parsed table, read once. The file is embedded, so a bad one is a build error found by the first test, never a runtime state.
var policyData = func() *Policy {
	var p Policy
	if err := json.Unmarshal(policyJSON, &p); err != nil {
		panic("tunnel/policy.json: " + err.Error())
	}
	return &p
}()

// secs turns a policy value in seconds into a Duration.
func secs(n int) time.Duration { return time.Duration(n) * time.Second }

// anchored compiles one of the policy's ^...$ patterns (RE2: `$` is the end of the text, so a trailing newline never matches).
func anchored(pattern string) *regexp.Regexp {
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		panic(fmt.Sprintf("policy patterns are anchored: %s", pattern))
	}
	return regexp.MustCompile(pattern)
}

// The patterns of the contracts, compiled from the policy and never written again.
var (
	reLabel    = anchored(policyData.Identity.LabelRegex)
	reFQDN     = anchored(policyData.Identity.FQDNRegex)
	reDeviceID = anchored(policyData.Identity.DeviceIDRegex)
	reStreamID = anchored(policyData.Identity.StreamIDRegex)
	reSecret   = anchored(policyData.Identity.AttachSecretRE)
	reNonce    = anchored(policyData.Identity.NonceRegex)
	reJTI      = anchored(policyData.Identity.JTIRegex)
	reKID      = anchored(policyData.Identity.KIDRegex)
)

// inList reports whether s is one of the words.
func inList(words []string, s string) bool {
	for _, w := range words {
		if w == s {
			return true
		}
	}
	return false
}

// validFQDN is the contracts' device host: exactly one label under a zone, at most the policy length.
func validFQDN(s string) bool {
	return len(s) <= policyData.Identity.FQDNMaxLength && reFQDN.MatchString(s)
}
