//go:build e2e_cloud

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	alidns "github.com/go-acme/alidns-20150109/v4/client"
	dnspod "github.com/go-acme/tencentclouddnspod/v20210323"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	sdkerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

// The environment variables that hold the keys of the DNS providers. The
// server container takes them from the environment of the test, and
// server.yaml refers to them, so no key is in a file or on a command line.
const (
	cloudflareTokenEnv       = "CERTFOLD_E2E_CLOUDFLARE_TOKEN"
	aliyunAccessKeyEnv       = "CERTFOLD_E2E_ALIYUN_ACCESS_KEY"
	aliyunAccessSecretEnv    = "CERTFOLD_E2E_ALIYUN_ACCESS_SECRET"
	tencentcloudSecretIDEnv  = "CERTFOLD_E2E_TENCENTCLOUD_SECRET_ID"
	tencentcloudSecretKeyEnv = "CERTFOLD_E2E_TENCENTCLOUD_SECRET_KEY"
)

// cloudIssuanceTimeout bounds the wait for every certificate, from the start
// of the server. Let's Encrypt staging issues each in tens of seconds, and the
// server issues them in parallel: the bound only limits how long a broken run
// waits.
const cloudIssuanceTimeout = 3 * time.Minute

// cloudProvider is a DNS provider the server can issue through.
type cloudProvider struct {
	// name is both the name and the type of the provider in server.yaml.
	name string
	// keys pairs each key of the provider in server.yaml with the
	// environment variable that holds it.
	keys [][2]string
	// zones are the zones the provider's certificates have names in.
	zones []string
	// txtRecords returns the name of every TXT record in zone whose name
	// contains label.
	txtRecords func(zone, label string) ([]string, error)
}

// The aliyun and tencentcloud zones are subdomains of certfold.org, which
// delegates them to Alibaba Cloud DNS and DNSPod.
var (
	cloudflare = &cloudProvider{
		name:       "cloudflare",
		keys:       [][2]string{{"api_token", cloudflareTokenEnv}},
		zones:      []string{"certfold.com", "certfold.org"},
		txtRecords: cloudflareTXTRecords,
	}
	aliyun = &cloudProvider{
		name:       "aliyun",
		keys:       [][2]string{{"access_key", aliyunAccessKeyEnv}, {"access_secret", aliyunAccessSecretEnv}},
		zones:      []string{"ali.certfold.org"},
		txtRecords: aliyunTXTRecords,
	}
	tencentcloud = &cloudProvider{
		name:       "tencentcloud",
		keys:       [][2]string{{"secret_id", tencentcloudSecretIDEnv}, {"secret_key", tencentcloudSecretKeyEnv}},
		zones:      []string{"tc.certfold.org"},
		txtRecords: tencentcloudTXTRecords,
	}
	cloudProviders = []*cloudProvider{cloudflare, aliyun, tencentcloud}
)

// unset returns the environment variables of p's keys that are not set.
func (p *cloudProvider) unset() []string {
	var names []string
	for _, key := range p.keys {
		if os.Getenv(key[1]) == "" {
			names = append(names, key[1])
		}
	}
	return names
}

// cloudServer is a certfolds server that issues its certificates from Let's
// Encrypt staging through the DNS providers whose keys are set. Its only
// file, server.yaml, is in runDir, in the bind mount.
type cloudServer struct {
	runtime   containerRuntime
	rootDir   string
	mountDir  string
	runDir    string
	image     string
	container string
	// label starts every domain of the run. Runs share no challenge record,
	// and the records a run leaves behind are found by it.
	label     string
	providers []*cloudProvider
	// skipped are the providers none of whose keys is set.
	skipped []*cloudProvider
	certs   []cloudCert
	started time.Time
}

// cloudCert is a certificate in the server's configuration. No two share a
// domain: they issue at once, and the challenges of one domain would collide.
type cloudCert struct {
	name     string
	provider *cloudProvider
	domains  []string
}

var cloud *cloudServer

// TestMain starts the server of the e2e_cloud tests, which issue real
// certificates for names in the project's zones. Unlike the e2e tests, they
// leave acme.dns_resolvers unset and keep the propagation check. They need
// outbound internet access from the container, and fail without a Cloudflare
// API token with DNS:Edit and Zone:Read on both zones. The keys of the other
// providers are optional: a provider without them issues nothing, and one
// with only some of them set is a mistake that fails the run.
func TestMain(m *testing.M) {
	if os.Getenv(cloudflareTokenEnv) == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: the e2e_cloud tests need a Cloudflare API token with DNS:Edit and Zone:Read on %s\n",
			cloudflareTokenEnv, strings.Join(cloudflare.zones, " and "))
		os.Exit(1)
	}
	for _, p := range cloudProviders {
		if unset := p.unset(); len(unset) > 0 && len(unset) < len(p.keys) {
			fmt.Fprintf(os.Stderr, "%s is not set, but other keys of %s are\n", strings.Join(unset, " and "), p.name)
			os.Exit(1)
		}
	}
	rt, err := detectContainerRuntime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	cloud, err = newCloudServer(rt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create e2e_cloud server: %v\n", err)
		os.Exit(1)
	}
	if err := cloud.start(); err != nil {
		fmt.Fprintf(os.Stderr, "start e2e_cloud server: %v\n", err)
		cloud.cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cloud.cleanup()
	os.Exit(code)
}

// TestCloudIssuance waits for the server to issue its certificates and checks
// each on its own, so that one failing hides none of the others. Then it
// checks that lego removed every challenge record of the run.
func TestCloudIssuance(t *testing.T) {
	for _, p := range cloud.skipped {
		t.Run(p.name, func(t *testing.T) {
			t.Skipf("%s not set", strings.Join(p.unset(), " and "))
		})
	}
	states, settled := cloud.waitForIssuance(t)
	for _, c := range cloud.certs {
		t.Run(c.name, func(t *testing.T) {
			cert, ok := states[c.name]
			if !ok {
				t.Fatalf("cert list has no %s", c.name)
			}
			took, ok := settled[c.name]
			if !ok {
				t.Fatalf("still %s %s after the server started; last_error: %s", cert.State, cloudIssuanceTimeout, cert.LastError)
			}
			if cert.State != "valid" {
				t.Fatalf("%s %s after the server started; last_error: %s", cert.State, took.Round(time.Second), cert.LastError)
			}
			if !cert.NotAfter.After(time.Now()) {
				t.Fatalf("certificate expired at %s", cert.NotAfter)
			}
			t.Logf("valid %s after the server started, expires %s", took.Round(time.Second), cert.NotAfter.Format(time.RFC3339))
		})
	}
	t.Run("no challenge records left", func(t *testing.T) {
		for _, p := range cloud.providers {
			for _, zone := range p.zones {
				names, err := p.txtRecords(zone, cloud.label)
				if err != nil {
					t.Errorf("%s: %v", zone, err)
					continue
				}
				if len(names) > 0 {
					// Nothing removes them: delete them by hand. A certificate
					// still issuing at the deadline leaves its records too,
					// since cleanup stops the server before lego removes them.
					t.Errorf("%s has TXT records of the run left, delete them by hand: %s", zone, strings.Join(names, ", "))
				}
			}
		}
	})
	// lego logs its progress for each domain, which tells where the time went.
	t.Logf("server logs:\n%s", cloud.logs())
}

func newCloudServer(rt containerRuntime) (*cloudServer, error) {
	rootDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return nil, err
	}
	mountDir, runDir, err := newRunDir()
	if err != nil {
		return nil, err
	}
	random := make([]byte, 4)
	_, _ = rand.Read(random)
	label := "e2e-" + hex.EncodeToString(random)
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().Unix())
	s := &cloudServer{
		runtime:   rt,
		rootDir:   rootDir,
		mountDir:  mountDir,
		runDir:    runDir,
		image:     "certfold-e2e-cloud-certfolds:" + suffix,
		container: "certfold-e2e-cloud-" + suffix,
		label:     label,
	}
	for _, p := range cloudProviders {
		if len(p.unset()) == 0 {
			s.providers = append(s.providers, p)
		} else {
			s.skipped = append(s.skipped, p)
		}
	}
	certs := []cloudCert{
		// The provider looks up the zone of each name.
		{name: "cross-zone", provider: cloudflare, domains: []string{label + "-a.certfold.com", label + "-a.certfold.org"}},
		// Both names have their challenge at one record name, which holds
		// both values at once.
		{name: "wildcard", provider: cloudflare, domains: []string{label + "-b.certfold.org", "*." + label + "-b.certfold.org"}},
		{name: "aliyun", provider: aliyun, domains: []string{label + ".ali.certfold.org", "*." + label + ".ali.certfold.org"}},
		{name: "tencentcloud", provider: tencentcloud, domains: []string{label + ".tc.certfold.org", "*." + label + ".tc.certfold.org"}},
	}
	for _, cert := range certs {
		if slices.Contains(s.providers, cert.provider) {
			s.certs = append(s.certs, cert)
		}
	}
	if err := s.writeConfig(); err != nil {
		_ = os.RemoveAll(runDir)
		return nil, err
	}
	return s, nil
}

func (s *cloudServer) writeConfig() error {
	var providers strings.Builder
	for _, p := range s.providers {
		fmt.Fprintf(&providers, "  %s:\n    type: %s\n", p.name, p.name)
		for _, key := range p.keys {
			fmt.Fprintf(&providers, "    %s: \"${%s}\"\n", key[0], key[1])
		}
	}
	var certs strings.Builder
	for _, cert := range s.certs {
		domains := make([]string, len(cert.domains))
		for i, domain := range cert.domains {
			domains[i] = fmt.Sprintf("%q", domain)
		}
		fmt.Fprintf(&certs, "  - name: %s\n    domains: [%s]\n    ca: letsencrypt-staging\n    dns_provider: %s\n",
			cert.name, strings.Join(domains, ", "), cert.provider.name)
	}
	// Let's Encrypt refuses contacts at example.com.
	config := fmt.Sprintf(`server:
  data_dir: %q

acme:
  email: "e2e@certfold.org"
  default_ca: letsencrypt-staging
  cas:
    letsencrypt-staging:
      directory: "https://acme-staging-v02.api.letsencrypt.org/directory"

dns_providers:
%s
certificates:
%s`, serverDataDir, providers.String(), certs.String())
	return os.WriteFile(filepath.Join(s.runDir, "server.yaml"), []byte(config), 0o600)
}

func (s *cloudServer) start() error {
	fmt.Printf("E2E: building certfolds with %s\n", s.runtime.name)
	if out, err := s.runtime.run(s.rootDir, "build", "-f", "test/e2e/Dockerfile.certfolds", "-t", s.image, "."); err != nil {
		return fmt.Errorf("build certfolds: %w\n%s", err, out)
	}
	s.started = time.Now()
	// No LEGO_CA_CERTIFICATES: lego trusts only those roots when it is set,
	// and Let's Encrypt chains to the system roots.
	args := []string{
		"run", "-d",
		"--name", s.container,
		"-e", "CERTFOLDS_CONFIG=" + strings.Join([]string{"/e2e", filepath.Base(s.runDir), "server.yaml"}, "/"),
	}
	for _, p := range s.providers {
		for _, key := range p.keys {
			args = append(args, "-e", key[1])
		}
	}
	args = append(args, "-v", bindMount(s.mountDir, "/e2e", false), s.image)
	if out, err := s.runtime.run(s.rootDir, args...); err != nil {
		return fmt.Errorf("start certfolds: %w\n%s", err, out)
	}
	return nil
}

// waitForIssuance polls cert list until every certificate is valid or in
// retry backoff, whose next attempt is minutes away, or until
// cloudIssuanceTimeout after the server started. It returns the last state of
// each certificate and, for each that settled, how long after the server
// started the poll found it so.
func (s *cloudServer) waitForIssuance(t *testing.T) (map[string]certState, map[string]time.Duration) {
	t.Helper()
	states := map[string]certState{}
	settled := map[string]time.Duration{}
	var last string
	for len(settled) < len(s.certs) && time.Since(s.started) < cloudIssuanceTimeout {
		// The command fails until the server's IPC endpoint is up.
		out, err := s.runtime.run(s.rootDir, "exec", s.container, "certfolds", "--json", "cert", "list")
		last = out
		if err == nil {
			var certs []certState
			if err := json.Unmarshal([]byte(out), &certs); err != nil {
				t.Fatalf("parse cert list: %v\n%s", err, out)
			}
			for _, cert := range certs {
				states[cert.Name] = cert
				if _, ok := settled[cert.Name]; !ok && (cert.State == "valid" || cert.State == "backoff") {
					settled[cert.Name] = time.Since(s.started)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	if len(states) == 0 {
		t.Fatalf("cert list did not answer within %s; last output:\n%s\nserver logs:\n%s", cloudIssuanceTimeout, last, s.logs())
	}
	return states, settled
}

// cloudflareTXTRecords returns the name of every TXT record in zone whose name
// contains label.
func cloudflareTXTRecords(zone, label string) ([]string, error) {
	var zones []struct {
		ID string `json:"id"`
	}
	if err := cloudflareGet("/zones?"+url.Values{"name": {zone}}.Encode(), &zones); err != nil {
		return nil, err
	}
	if len(zones) != 1 {
		return nil, fmt.Errorf("the token sees %d zones named %s, want 1", len(zones), zone)
	}
	var records []struct {
		Name string `json:"name"`
	}
	query := url.Values{"type": {"TXT"}, "name.contains": {label}, "per_page": {"100"}}
	if err := cloudflareGet("/zones/"+zones[0].ID+"/dns_records?"+query.Encode(), &records); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, record.Name)
	}
	return names, nil
}

// cloudflareGet gets path from the Cloudflare API and decodes the result of
// the answer into result.
func cloudflareGet(path string, result any) error {
	req, err := http.NewRequest(http.MethodGet, "https://api.cloudflare.com/client/v4"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv(cloudflareTokenEnv))
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		Success bool            `json:"success"`
		Errors  json.RawMessage `json:"errors"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("GET %s: status %d: %w", path, resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || !body.Success {
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, body.Errors)
	}
	return json.Unmarshal(body.Result, result)
}

// aliyunTXTRecords returns the name of every TXT record in zone whose name
// contains label. It builds its client as lego's alidns provider does.
func aliyunTXTRecords(zone, label string) ([]string, error) {
	client, err := alidns.NewClient(new(openapi.Config).
		SetRegionId("cn-hangzhou").
		SetAccessKeyId(os.Getenv(aliyunAccessKeyEnv)).
		SetAccessKeySecret(os.Getenv(aliyunAccessSecretEnv)))
	if err != nil {
		return nil, err
	}
	resp, err := alidns.DescribeDomainRecords(client, &alidns.DescribeDomainRecordsRequest{
		DomainName:  dara.String(zone),
		TypeKeyWord: dara.String("TXT"),
		RRKeyWord:   dara.String(label),
		PageSize:    dara.Int64(100),
	})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, record := range resp.Body.DomainRecords.Record {
		names = append(names, dara.StringValue(record.RR)+"."+zone)
	}
	return names, nil
}

// tencentcloudTXTRecords returns the name of every TXT record in zone at the
// challenge name of label, the only name the run uses there. It builds its
// client and asks for the record name as lego's tencentcloud provider does.
func tencentcloudTXTRecords(zone, label string) ([]string, error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
	client, err := dnspod.NewClient(common.NewCredential(os.Getenv(tencentcloudSecretIDEnv), os.Getenv(tencentcloudSecretKeyEnv)), "", cpf)
	if err != nil {
		return nil, err
	}
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordType = common.StringPtr("TXT")
	req.Subdomain = common.StringPtr("_acme-challenge." + label)
	resp, err := dnspod.DescribeRecordList(client, req)
	var sdkErr *sdkerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) && sdkErr.Code == dnspod.RESOURCENOTFOUND_NODATAOFRECORD {
		// DNSPod answers an empty list with this error.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, record := range resp.Response.RecordList {
		names = append(names, dara.StringValue(record.Name)+"."+zone)
	}
	return names, nil
}

func (s *cloudServer) logs() string {
	out, _ := s.runtime.run(s.rootDir, "logs", s.container)
	return out
}

func (s *cloudServer) cleanup() {
	_, _ = s.runtime.removeContainer(s.rootDir, s.container)
	_, _ = s.runtime.run(s.rootDir, "rmi", "-f", s.image)
	_ = os.RemoveAll(s.runDir)
}
