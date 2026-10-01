package config

import (
	"strings"
	"testing"
)

// The inline map of a DNS provider takes any key, and the issuer
// (buildDNSProvider in internal/acme) reads only a fixed set per type, and
// only strings. A typo or an AWS-style key name would be dropped silently:
// route53 would then sign with the ambient AWS credentials, gcloud with
// application default credentials.
func TestDNSProviderRejectsKeysTheIssuerIgnores(t *testing.T) {
	t.Setenv("CERTFOLD_TEST_DIGITS", "12345")
	for _, tt := range []struct {
		name, block, want string
	}{
		{
			name:  "route53 AWS-style key names",
			block: "  r53:\n    type: route53\n    access_key_id: AKIA\n    secret_access_key: s\n",
			want:  `dns_providers.r53.access_key_id: unknown field for provider type "route53" (supported: access_key, secret_key, region)`,
		},
		{
			name:  "route53 non-string region",
			block: "  r53:\n    type: route53\n    region: 1\n",
			want:  "dns_providers.r53.region: must be a string",
		},
		{
			name:  "cloudflare misspelled skip",
			block: "  cf2:\n    type: cloudflare\n    api_token: t\n    skip_propagation: true\n",
			want:  `dns_providers.cf2.skip_propagation: unknown field for provider type "cloudflare"`,
		},
		{
			name:  "gcloud misspelled file",
			block: "  g:\n    type: gcloud\n    project: p\n    service_acount_file: /x.json\n",
			want:  `dns_providers.g.service_acount_file: unknown field for provider type "gcloud"`,
		},
		{
			name:  "digits expanded into a plain scalar",
			block: "  cf2:\n    type: cloudflare\n    api_token: ${CERTFOLD_TEST_DIGITS}\n",
			want:  "dns_providers.cf2.api_token: must be a string",
		},
		{
			name:  "boolean",
			block: "  ali:\n    type: aliyun\n    access_key: true\n    access_secret: s\n",
			want:  "dns_providers.ali.access_key: must be a string",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := strings.Replace(validServerYAML, "dns_providers:\n", "dns_providers:\n"+tt.block, 1)
			_, err := ParseServer([]byte(src))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %s", err, tt.want)
			}
		})
	}
}

// A value of another type is reported once, as not a string: not also as
// missing.
func TestDNSProviderValueOfAnotherTypeIsNotReportedMissing(t *testing.T) {
	src := strings.Replace(validServerYAML, `access_key: "k"`, "access_key: 123", 1)
	_, err := ParseServer([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "dns_providers.aliyun-a.access_key: must be a string") {
		t.Fatalf("error = %v, want access_key reported as not a string", err)
	}
	if strings.Contains(err.Error(), "required") {
		t.Fatalf("error = %v, also reports access_key as missing", err)
	}
}

// A quoted value stays a string whatever it holds, and a null value, which
// ${VAR:-} gives for an optional key, is not set.
func TestDNSProviderStringsAndNullValues(t *testing.T) {
	t.Setenv("CERTFOLD_TEST_DIGITS", "12345")
	block := "  cf2:\n    type: cloudflare\n    api_token: \"${CERTFOLD_TEST_DIGITS}\"\n    zone_api_token: ${CERTFOLD_TEST_UNSET:-}\n" +
		"  r53:\n    type: route53\n    region: \"1\"\n    access_key:\n    secret_key: ~\n"
	cfg, err := ParseServer([]byte(strings.Replace(validServerYAML, "dns_providers:\n", "dns_providers:\n"+block, 1)))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	cf := cfg.DNSProviders["cf2"].Config
	if cf["api_token"] != "12345" || cf["zone_api_token"] != nil {
		t.Fatalf("cloudflare config = %#v", cf)
	}

	// A required value that is null, or an empty string, such as a quoted
	// ${VAR} whose variable is set but empty, is missing.
	t.Setenv("CERTFOLD_TEST_EMPTY", "")
	for _, value := range []string{"${CERTFOLD_TEST_UNSET:-}", `"${CERTFOLD_TEST_EMPTY}"`} {
		src := strings.Replace(validServerYAML, `access_key: "k"`, "access_key: "+value, 1)
		if _, err := ParseServer([]byte(src)); err == nil || !strings.Contains(err.Error(), `dns_providers.aliyun-a.access_key: required for provider type "aliyun"`) {
			t.Errorf("access_key: %s: error = %v, want access_key reported as missing", value, err)
		}
	}
}
