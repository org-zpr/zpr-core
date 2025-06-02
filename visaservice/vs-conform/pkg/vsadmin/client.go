package vsadmin

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"zpr.org/vsx/polio"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

const SerialVersion = 43

type Client struct {
	vsaddr netip.AddrPort
	zlog   *zap.SugaredLogger
}

type PolicyVersion struct {
	ConfigId uint64 `json:"config_id"`
	Version  string `json:"version"`
}

type PolicyEncap struct {
	ConfigId  uint64 `json:"config_id"`
	Container string `json:"container"`
	Format    string `json:"format"`
	Version   string `json:"version"`
}

type VisaDescriptor struct {
	VisaId     uint64 `json:"id"`
	Expiration uint64 `json:"expires"`
	Source     string `json:"source"`
	Dest       string `json:"dest"`
}

// see `core/pkg/vservice/adb/actordb.go`
type HostRecordBrief struct {
	CTime   int64      `json:"ctime"` // unix seconds
	Cn      string     `json:"cn"`
	ZPRAddr netip.Addr `json:"zpr_addr"`
	Ident   string     `json:"ident"`
	Node    bool       `json:"node"`
}

// see `core/pkg/vservice/admin.go`
type RevokeResponse struct {
	Revoked string `json:"revoked"`
	Count   uint32 `json:"count"`
}

// see `core/pkg/vservice/admin.go`
type RevokeAdminRequest struct {
	ClearAll bool `json:"clear_all"` // TRUE clear all revocation data, FALSE is NOP
}

// see `core/pkg/vservice/admin.go`
type RevokeAdminResponse struct {
	ClearCount uint32 `json:"clear_count"`
}

func NewVSAdminClient(vsaddr netip.AddrPort, zlog *zap.Logger) (*Client, error) {
	return &Client{
		vsaddr: vsaddr,
		zlog:   zlog.Sugar(),
	}, nil
}

func (c *Client) GetCurrentPolicy() (*polio.Policy, error) {
	plist, err := c.ListPolicies()
	if err != nil {
		return nil, err
	}
	if len(plist) == 0 {
		return nil, fmt.Errorf("no policies found in visa service")
	}
	if len(plist) > 1 {
		return nil, fmt.Errorf("multiple policies found in visa service, expected only one")
	}
	c.zlog.Infow("policy advertised", "config_id", plist[0].ConfigId, "version", plist[0].Version)
	encap, err := c.GetPolicy(plist[0].ConfigId)
	if err != nil {
		return nil, err
	}

	return c.deserializePolicy(encap.Format, encap.Container)
}

func (c *Client) deserializePolicy(format string, encap string) (*polio.Policy, error) {
	formatParts := strings.Split(format, ";")
	if len(formatParts) != 3 {
		return nil, fmt.Errorf("invalid format string: %s", format)
	}
	if formatParts[0] != "base64" {
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
	zdata, err := base64.StdEncoding.DecodeString(encap)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding failed: %w", err)
	}
	if formatParts[1] != "zip" {
		return nil, fmt.Errorf("unsupported compression format: %s", format)
	}
	sver, err := strconv.Atoi(formatParts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid policy container version: %s: %w", formatParts[2], err)
	}
	if sver != SerialVersion {
		return nil, fmt.Errorf("unsupported policy container version: got %d, expect %d", sver, SerialVersion)
	}
	pc, err := decompress(zdata)
	if err != nil {
		return nil, fmt.Errorf("decompress/unmarshal failed: %w", err)
	}
	c.zlog.Infow("policy container loaded", "version", pc.GetContainerVersion())
	pol, err := ReleasePolicy(pc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to release policy: %v", err)
	}
	return pol, nil
}

func (c *Client) newHttpClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: tr,
	}
}

func (c *Client) htGet(url string) (*http.Response, error) {
	c.zlog.Infow("GET", "url", url)
	resp, err := c.newHttpClient().Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get %s, got status: %s", url, resp.Status)
	}
	return resp, nil
}

func (c *Client) ListPolicies() ([]*PolicyVersion, error) {
	resp, err := c.htGet(fmt.Sprintf("https://%s/admin/policies", c.vsaddr))
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %v", err)
	}
	defer resp.Body.Close()
	jsdata, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var plist []*PolicyVersion
	if err := json.Unmarshal(jsdata, &plist); err != nil {
		return nil, fmt.Errorf("failed to decode policy-list json: %v", err)
	}
	return plist, err
}

func (c *Client) GetPolicy(configId uint64) (*PolicyEncap, error) {
	resp, err := c.htGet(fmt.Sprintf("https://%s/admin/policy/%d/current", c.vsaddr, configId))
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %v", err)
	}
	defer resp.Body.Close()
	jsdata, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var encap PolicyEncap
	if err := json.Unmarshal(jsdata, &encap); err != nil {
		return nil, fmt.Errorf("failed to decode policy json: %v", err)
	}
	return &encap, nil
}

func (c *Client) ListVisas() ([]*VisaDescriptor, error) {
	resp, err := c.htGet(fmt.Sprintf("https://%s/admin/visas", c.vsaddr))
	if err != nil {
		return nil, fmt.Errorf("failed to list visas: %v", err)
	}
	defer resp.Body.Close()
	jsdata, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var vlist []*VisaDescriptor
	if err := json.Unmarshal(jsdata, &vlist); err != nil {
		return nil, fmt.Errorf("failed to decode visa-list json: %v", err)
	}
	return vlist, err
}

func (c *Client) RevokeVisa(visaId uint64) error {
	c.zlog.Infow("api revoke visa", "ID", visaId)
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("https://%s/admin/visas/%d", c.vsaddr, visaId), nil)
	if err != nil {
		return err
	}
	resp, err := c.newHttpClient().Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete visa %d, got status: %s", visaId, resp.Status)
	}
	return nil
}

func (c *Client) ListActors() ([]*HostRecordBrief, error) {
	resp, err := c.htGet(fmt.Sprintf("https://%s/admin/actors", c.vsaddr))
	if err != nil {
		return nil, fmt.Errorf("failed to list actors: %v", err)
	}
	defer resp.Body.Close()
	jsdata, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var alist []*HostRecordBrief
	if err := json.Unmarshal(jsdata, &alist); err != nil {
		return nil, fmt.Errorf("failed to decode actors-list json: %v", err)
	}
	return alist, err
}

// DeleteActor will not only try to remove existing visas for the CN, but will install a
// revocation into visa service state which will prevent new visas from being issues for the CN.
// Use Client.ClearAllRevokes to reset visa service state.
func (c *Client) RevokeActor(actorCN string) (*RevokeResponse, error) {
	c.zlog.Infow("api delete actor", "cn", actorCN)
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("https://%s/admin/actors/%s", c.vsaddr, actorCN), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.newHttpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to delete actor by CN %s, got status: %s", actorCN, resp.Status)
	}
	defer resp.Body.Close()
	jsdata, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rr RevokeResponse
	if err := json.Unmarshal(jsdata, &rr); err != nil {
		return nil, fmt.Errorf("failed to decode revoke-response json: %v", err)
	}
	return &rr, nil
}

// ClearAllRevokes will remove all revocations from visa service state, returns the number of revocations removed
// as reported by the API.
func (c *Client) ClearAllRevokes() (int, error) {
	c.zlog.Infow("api clear all revokes")
	rreq := RevokeAdminRequest{
		ClearAll: true,
	}
	buf, err := json.Marshal(rreq)
	if err != nil {
		return 0, err
	}
	rdr := bytes.NewReader(buf)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/admin/revokes", c.vsaddr), rdr)
	if err != nil {
		return 0, err
	}
	resp, err := c.newHttpClient().Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("clear all revokes failed, got status: %s", resp.Status)
	}
	defer resp.Body.Close()
	jsdata, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	var rr RevokeAdminResponse
	if err := json.Unmarshal(jsdata, &rr); err != nil {
		return 0, fmt.Errorf("failed to decode revoke-admin-response json: %v", err)
	}
	return int(rr.ClearCount), nil
}

// Decompress decompresses and unmarshalls a PolicyContainer.
// Copied from core/pkg/libvisa.
func decompress(buf []byte) (*polio.PolicyContainer, error) {
	rdr := bytes.NewReader(buf)
	zr, err := gzip.NewReader(rdr)
	if err != nil {
		return nil, err
	}
	// Copy compressed data into a buffer:
	tmp := &bytes.Buffer{}
	if _, err := io.Copy(tmp, zr); err != nil {
		return nil, err
	}
	if err := zr.Close(); err != nil {
		return nil, err
	}
	pc := &polio.PolicyContainer{}
	if err := proto.Unmarshal(tmp.Bytes(), pc); err != nil {
		return nil, err
	}
	return pc, nil
}

// ReleasePolicy unwraps a policy, also checks schema version. If `pubkey` is
// non-nil checks signature.
// Copied from core/policy/container.go
func ReleasePolicy(pc *polio.PolicyContainer, pubkey *rsa.PublicKey) (*polio.Policy, error) {
	if pubkey != nil {
		hashed := sha256.Sum256(pc.Policy)
		if err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed[:], pc.GetSignature()); err != nil {
			return nil, err
		}
	}
	polbun := &polio.Policy{}
	if err := proto.Unmarshal(pc.GetPolicy(), polbun); err != nil {
		return nil, err
	}
	if polbun.GetSerialVersion() != SerialVersion {
		return nil, fmt.Errorf("schema version mismatch, got %d expected %d", polbun.GetSerialVersion(), SerialVersion)
	}
	// Restore fields that were omitted from the signature.
	polbun.PolicyDate = pc.PolicyDate
	polbun.PolicyRevision = pc.PolicyRevision
	polbun.PolicyMetadata = pc.PolicyMetadata
	return polbun, nil
}
