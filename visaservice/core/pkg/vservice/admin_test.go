package vservice_test

/* DISABLED UNTIL WE SORT OUT COMPILER
import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/compiler"
	"zpr.org/vsx/zpl/fs"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"google.golang.org/protobuf/proto"
)

const basic_policy_1 = `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            provider:
              - [ca0.foo, eq, fox]
            admin_attrs:
              - [ca0.foo, eq, fee]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              provider:
                - [ca0.x509.cn, eq, n0.internal]
              address: "fc00:3001:1::11"
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"

          datasources:
            ca0:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]

        communications:
          systems:
            mathiasland:
              desc: mathiasland
        `

func createPolicyFile(t *testing.T, pyaml string, privateKey *rsa.PrivateKey) (policyFileName string, policyVersion string) {
	pc := compilePolicyToContainer(t, pyaml, privateKey)

	pcData, err := proto.Marshal(pc)
	require.Nil(t, err)

	policyVersion = fmt.Sprintf("%d+%v", pc.PolicyVersion, pc.PolicyRevision)

	tfile, err := os.CreateTemp("", "test-admin-list.policy")
	require.Nil(t, err)
	if err := os.WriteFile(tfile.Name(), pcData, 0644); err != nil {
		os.Remove(tfile.Name())
		require.Nil(t, err)
	}
	tfile.Close()
	policyFileName = tfile.Name()
	return
}

func compilePolicyToContainer(t *testing.T, pyaml string, privateKey *rsa.PrivateKey) *polio.PolicyContainer {
	// Compile and install the policy
	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "foo1",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	pc, err := policy.ContainPolicy(plcy, privateKey)
	require.Nil(t, err)
	return pc
}

// little hack to get a free port number
func GetFreePort() (port uint16, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return uint16(l.Addr().(*net.TCPAddr).Port), nil
		}
	}
	return
}

// eg, partialURL = "/admin/policies" (must start with slash)
func doHTTPSGet(t *testing.T, port uint16, partialURL string, alog *logr.TestLogger) (*http.Response, error) {

	fullURL := fmt.Sprintf("https://127.0.0.1:%d%s", port, partialURL)

	cliconf := &tls.Config{InsecureSkipVerify: true}
	cliTransport := &http.Transport{
		TLSClientConfig: cliconf,
	}
	client := &http.Client{Transport: cliTransport}
	retry := 0
	var resp *http.Response
	var err error
	for retry < 5 {
		alog.Info("< TEST > GET", "url", fullURL)
		resp, err = client.Get(fullURL)
		if err == nil {
			break
		}
		alog.WithError(err).Info("< TEST > retrying...")
		time.Sleep(200 * time.Millisecond)
		retry++
		continue
	}
	return resp, err
}

// Does not retry
func doHTTPSPost(t *testing.T, port uint16, partialURL string, body []byte, alog *logr.TestLogger) (*http.Response, error) {

	fullURL := fmt.Sprintf("https://127.0.0.1:%d%s", port, partialURL)

	cliconf := &tls.Config{InsecureSkipVerify: true}
	cliTransport := &http.Transport{
		TLSClientConfig: cliconf,
	}
	client := &http.Client{Transport: cliTransport}

	buf := bytes.NewBuffer(body)
	resp, err := client.Post(fullURL, "application/json", buf)

	return resp, err
}

// Make this little test suite so that I can ensure that we stop the visa service go-routine.
type VSRunnerSuite struct {
	suite.Suite
	svc *vservice.VisaService
}

func TestVSRunnerSuite(t *testing.T) {
	suite.Run(t, new(VSRunnerSuite))
}

func (suite *VSRunnerSuite) SetupTest() {
	suite.svc = nil
}

func (suite *VSRunnerSuite) TearDownTest() {
	if suite.svc != nil {
		suite.svc.Stop()
	}
}

func (suite *VSRunnerSuite) TestAdminListPolicy() {
	t := suite.T()
	alog := logr.NewTestLogger()

	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)

	// visa service reads a binary "policy container" file
	policyFileName, policyVersion := createPolicyFile(t, basic_policy_1, privateKey)
	defer os.Remove(policyFileName)

	cer, err := tls.X509KeyPair([]byte(testCert), []byte(testPrivakeKey))
	require.Nil(t, err)

	serverCreds := &tls.Config{Certificates: []tls.Certificate{cer}}

	authorityCert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)

	svc, err := vservice.NewVisaService(policyFileName, "cn_missing", privateKey, serverCreds, 1*time.Hour, 1*time.Hour, authorityCert, alog)
	require.Nil(t, err)
	suite.svc = svc

	vsPort, err := GetFreePort()
	require.Nil(t, err)
	adminPort, err := GetFreePort()
	require.Nil(t, err)

	go func() {
		alog.Info("< TEST > starting visa service")
		if err := svc.Start("vs0", netip.MustParseAddr("127.0.0.1"), vsPort, adminPort); err != nil {
			alog.WithError(err).Info("< TEST > visa service has stopped")
		} else {
			alog.Info("< TEST > visa service has stopped")
		}
	}()

	alog.Info("< TEST > allowing visa service time to start up...")

	// Wait for visa service to initialize.  We will also retry.
	time.Sleep(1500 * time.Millisecond)

	resp, err := doHTTPSGet(t, adminPort, "/admin/policies", alog)

	svc.Stop()
	suite.svc = nil

	require.Nil(t, err)
	require.NotEmpty(t, resp.Body)

	var pols []*vservice.PolicyListEntry
	err = json.NewDecoder(resp.Body).Decode(&pols)
	require.Nil(t, err)

	require.Equal(t, 1, len(pols))
	require.Equal(t, policyVersion, pols[0].Version)
	require.NotZero(t, pols[0].ConfigId) // will be something like YYYYMMDD00001
}

func (suite *VSRunnerSuite) TestGetCurrentPolicy() {
	t := suite.T()
	alog := logr.NewTestLogger()

	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)

	// visa service reads a binary "policy container" file
	policyFileName, _ := createPolicyFile(t, basic_policy_1, privateKey)
	defer os.Remove(policyFileName)

	cer, err := tls.X509KeyPair([]byte(testCert), []byte(testPrivakeKey))
	require.Nil(t, err)

	serverCreds := &tls.Config{Certificates: []tls.Certificate{cer}}

	authorityCert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)

	svc, err := vservice.NewVisaService(policyFileName, "cn_missing", privateKey, serverCreds, 1*time.Hour, 1*time.Hour, authorityCert, alog)
	require.Nil(t, err)
	suite.svc = svc

	vsPort, err := GetFreePort()
	require.Nil(t, err)
	adminPort, err := GetFreePort()
	require.Nil(t, err)

	go func() {
		alog.Info("< TEST > starting visa service")
		if err := svc.Start("vs0", netip.MustParseAddr("127.0.0.1"), vsPort, adminPort); err != nil {
			alog.WithError(err).Info("< TEST > visa service has stopped")
		} else {
			alog.Info("< TEST > visa service has stopped")
		}
	}()

	alog.Info("< TEST > allowing visa service time to start up...")

	// Wait for visa service to initialize.  We will also retry.
	time.Sleep(1500 * time.Millisecond)

	// First we need to get the config ID
	resp, err := doHTTPSGet(t, adminPort, "/admin/policies", alog)
	require.Nil(t, err)

	var pols []*vservice.PolicyListEntry
	err = json.NewDecoder(resp.Body).Decode(&pols)
	require.Nil(t, err)

	require.Equal(t, 1, len(pols))
	configID := pols[0].ConfigId

	resp, err = doHTTPSGet(t, adminPort, fmt.Sprintf("/admin/policy/%d/current", configID), alog)

	svc.Stop()
	suite.svc = nil

	require.Nil(t, err)

	var bundle vservice.PolicyBundle
	err = json.NewDecoder(resp.Body).Decode(&bundle)
	require.Nil(t, err)

	require.Equal(t, configID, bundle.ConfigID)
	require.NotEmpty(t, bundle.Container)

	zdata, err := base64.StdEncoding.DecodeString(bundle.Container)
	require.Nil(t, err)

	pc, err := libvisa.Decompress(zdata)
	require.Nil(t, err)
	require.NotZero(t, pc.GetPolicyVersion())
}

func (suite *VSRunnerSuite) TestInstallPolicy() {
	t := suite.T()
	alog := logr.NewTestLogger()

	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)

	// visa service reads a binary "policy container" file
	policyFileName, _ := createPolicyFile(t, basic_policy_1, privateKey)
	defer os.Remove(policyFileName)

	cer, err := tls.X509KeyPair([]byte(testCert), []byte(testPrivakeKey))
	require.Nil(t, err)

	serverCreds := &tls.Config{Certificates: []tls.Certificate{cer}}

	authorityCert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)

	svc, err := vservice.NewVisaService(policyFileName, "cn_missing", privateKey, serverCreds, 1*time.Hour, 1*time.Hour, authorityCert, alog)
	require.Nil(t, err)
	suite.svc = svc

	vsPort, err := GetFreePort()
	require.Nil(t, err)
	adminPort, err := GetFreePort()
	require.Nil(t, err)

	go func() {
		alog.Info("< TEST > starting visa service")
		if err := svc.Start("vs0", netip.MustParseAddr("127.0.0.1"), vsPort, adminPort); err != nil {
			alog.WithError(err).Info("< TEST > visa service has stopped")
		} else {
			alog.Info("< TEST > visa service has stopped")
		}
	}()

	alog.Info("< TEST > allowing visa service time to start up...")

	// Wait for visa service to initialize.  We will also retry.
	time.Sleep(1500 * time.Millisecond)

	// Just changed a couple of attributes
	newpolicy := `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            provider:
              - [ca0.foo, eq, father]
            admin_attrs:
              - [ca0.foo, eq, christmas]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              provider:
                - [ca0.x509.cn, eq, n0.internal]
              address: "fc00:3001:1::11"
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"

          datasources:
            ca0:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]

        communications:
          systems:
            mathiasland:
              desc: mathiasland
        `

	bundle := new(vservice.PolicyBundle)
	bundle.Format = fmt.Sprintf("base64;zip;%d", policy.SerialVersion)

	pc := compilePolicyToContainer(t, newpolicy, privateKey)
	zdata, err := libvisa.Compress(pc)
	require.Nil(t, err)
	bundle.Container = base64.StdEncoding.EncodeToString(zdata)

	// Before installing lets get the current version so we can see it is different.
	newVersionExpected := fmt.Sprintf("%d+%v", pc.PolicyVersion, pc.PolicyRevision)

	resp, err := doHTTPSGet(t, adminPort, "/admin/policies", alog)
	require.Nil(t, err)
	var pols []*vservice.PolicyListEntry
	err = json.NewDecoder(resp.Body).Decode(&pols)
	require.Nil(t, err)
	require.Equal(t, 1, len(pols))
	require.NotEqual(t, newVersionExpected, pols[0].Version)

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(bundle)
	require.Nil(t, err)

	resp, err = doHTTPSPost(t, adminPort, "/admin/policy", buf.Bytes(), alog)
	require.Nil(t, err)

	var entry vservice.PolicyListEntry
	err = json.NewDecoder(resp.Body).Decode(&entry)
	require.Nil(t, err)
	require.Equal(t, newVersionExpected, entry.Version)
}
*/
