package vservice

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/net/context"

	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"

	"zpr.org/vsx/polio"
)

// 'admin.go' implements the parts of the admin service applicable to the visa service.
// Converted to HTTPS from original gRPC in prototype.

type PolicyListEntry struct {
	ConfigId uint64 `json:"config_id"`
	Version  string `json:"version"`
}

type PolicyBundle struct {
	ConfigID  uint64 `json:"config_id"` // only set when fetching a policy, ignored when installing.
	Version   string `json:"version"`   // when installing, this is the expected version of the policy we will replace.
	Format    string `json:"format"`    // eg, "base64;zip;<SERIAL_VERSION>"
	Container string `json:"container"` // base-64 encoded, zlib compressed PolicyContainer
}

// Visa Service API that admin service needs to do its job.
type VSApi interface {
	GetPolicyAndConfig() (*policy.Policy, uint64)
	InstallPolicy(*polio.ContainedPolicy) (string, uint64, error) // returns (version, config_id, error)
}

type AdminService struct {
	log               logr.Logger
	creds             *tls.Config
	policyCheckingKey *rsa.PublicKey // for checking policy signature
	vsi               VSApi

	installMtx sync.Mutex

	service struct {
		localAddr netip.Addr // local service address
		srvWg     sync.WaitGroup
		srv       *http.Server
	}
}

// NewAdminService creates the service. Call `StartAdminService` to start it.
func NewAdminService(log logr.Logger, tlsConfig *tls.Config, policyCheckKey *rsa.PublicKey, vsi VSApi) *AdminService {
	return &AdminService{
		log:               log,
		creds:             tlsConfig,
		policyCheckingKey: policyCheckKey,
		vsi:               vsi,
	}
}

// Blocking function
func (svc *AdminService) StartAdminService(listenAddr netip.Addr, port int) error {

	router := mux.NewRouter()
	router.HandleFunc("/admin/policies", svc.handleListPolicies).Methods("GET")
	router.HandleFunc("/admin/policy/{config_id}/current", svc.handleGetCurrentPolicy).Methods("GET")
	router.HandleFunc("/admin/policy", svc.handleInstallPolicy).Methods("POST")

	server := http.Server{
		Addr:         fmt.Sprintf("%v:%d", listenAddr.String(), port),
		Handler:      router,
		TLSConfig:    svc.creds,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		// ErrorLog:     TODO: wrap the log.Logger to we capture logging to our own logger.
	}

	svc.service.srvWg.Add(1)
	defer svc.service.srvWg.Done()
	svc.log.Infof("admin service starts on %v", server.Addr)
	svc.service.srv = &server
	err := server.ListenAndServeTLS("", "")
	svc.log.Errorf("admin service exited with error: %v", err)
	return err
}

// Stop server, blocking until complete.
func (svc *AdminService) StopAdminService() {
	if svc.service.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		svc.service.srv.Shutdown(ctx)
		svc.service.srvWg.Wait()
		svc.service.srv = nil
	}
}

// Returns a PolicyBundle json object
func (svc *AdminService) handleGetCurrentPolicy(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)

	pcy, configID := svc.vsi.GetPolicyAndConfig()
	if pcy == nil {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	configIDStr := params["config_id"]
	if fmt.Sprintf("%d", configID) != configIDStr {
		http.Error(w, "config_id unknown", http.StatusBadRequest)
		return
	}

	zbuf, err := libvisa.Compress(pcy.Export())
	if err != nil {
		svc.log.WithError(err).Error("admin service: failed to serialized policy, aborting fetch request")
		http.Error(w, "policy serialization failed", http.StatusInternalServerError)
		return
	}

	svc.log.Debug("admin server: fetch request processed successfully", "config", configID, "version", pcy.Version())
	bundle := &PolicyBundle{
		ConfigID:  configID,
		Version:   pcy.Version(),
		Format:    fmt.Sprintf("base64;zip;%d", pcy.GetSerialVersion()),
		Container: base64.StdEncoding.EncodeToString(zbuf),
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func (svc *AdminService) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	pcy, configID := svc.vsi.GetPolicyAndConfig()
	pver := "(none)"
	if pcy != nil {
		pver = pcy.VersionAndRevision()
	}
	resp := []*PolicyListEntry{
		{
			ConfigId: configID,
			Version:  pver,
		},
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Pass a PolicyBundle json object, returns a PolicyListEntry.
// ConfigID should be left blank.
// If version is set, then it is interpreted as the expected version of the existing policy.
func (svc *AdminService) handleInstallPolicy(w http.ResponseWriter, r *http.Request) {
	var bundle PolicyBundle

	err := json.NewDecoder(r.Body).Decode(&bundle)
	if err != nil {
		svc.log.WithError(err).Error("admin service: failed to unmarshal policy bundle, policy install aborted")
		http.Error(w, "policy unmarshal failed", http.StatusBadRequest)
		return
	}

	svc.installMtx.Lock()
	defer svc.installMtx.Unlock()

	currentP, _ := svc.vsi.GetPolicyAndConfig()
	if bundle.Version != "" {
		if currentP != nil && currentP.Version() != bundle.Version {
			http.Error(w, "expected version mismatch", http.StatusPreconditionFailed)
			return
		}
	}

	expectFormat := fmt.Sprintf("base64;zip;%d", polio.SerialVersion)

	if bundle.Format != expectFormat {
		http.Error(w, "incompatible policy serialization schema", http.StatusBadRequest)
		return
	}

	zbuf, err := base64.StdEncoding.DecodeString(bundle.Container)
	if err != nil {
		svc.log.WithError(err).Error("admin service: failed to decode base64 policy container")
		http.Error(w, "base64 decode failed", http.StatusBadRequest)
		return
	}

	polcont, err := libvisa.Decompress(zbuf)
	if err != nil {
		svc.log.WithError(err).Error("admin service: failed to unmarshal policy byndle, policy install aborted")
		http.Error(w, "policy unmarshal failed", http.StatusBadRequest)
		return
	}
	containedPol, err := polio.OpenContainedPolicy(polcont, svc.policyCheckingKey)
	if err != nil {
		svc.log.WithError(err).Error("admin service: failed to open policy container")
		http.Error(w, "policy open failed", http.StatusBadRequest)
		return
	}
	pversion, configID, err := svc.vsi.InstallPolicy(containedPol)
	if err != nil {
		svc.log.WithError(err).Error("admin service: failed to install policy")
		http.Error(w, "policy install failed", http.StatusInternalServerError)
		return
	}

	entry := &PolicyListEntry{
		ConfigId: configID,
		Version:  pversion,
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}
