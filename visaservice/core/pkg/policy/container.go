package policy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	fmt "fmt"
	"os"

	"google.golang.org/protobuf/proto"
	"zpr.org/vsx/polio"
)

type ContainedPolicy struct {
	Policy    *polio.Policy
	Container *polio.PolicyContainer // includes `Policy` in binary, signed form.
}

// If `pubKey` is non-nil, the signature is checked.
func OpenContainedPolicyFile(fname string, pubKey *rsa.PublicKey) (*ContainedPolicy, error) {
	pdata, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	// Decode the policy to get the format version.
	polc := &polio.PolicyContainer{}
	if err := proto.Unmarshal(pdata, polc); err != nil {
		return nil, fmt.Errorf("policy deserialization failed: %v", err)
	}

	// This will be checked on install too, but we do it quickly here too.
	pcy, err := ReleasePolicy(polc, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy container: %v", err)
	}
	if pcy.GetSerialVersion() != SerialVersion {
		return nil, fmt.Errorf("policy schema version mismatch, got %d expect %d", pcy.GetSerialVersion(), SerialVersion)
	}

	return &ContainedPolicy{
		Policy:    pcy,
		Container: polc,
	}, nil
}

// If `pubKey` is non-nil, the signature is checked.
func OpenContainedPolicy(polc *polio.PolicyContainer, pubKey *rsa.PublicKey) (*ContainedPolicy, error) {
	// This will be checked on install too, but we do it quickly here too.
	pcy, err := ReleasePolicy(polc, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy container: %v", err)
	}
	if pcy.GetSerialVersion() != SerialVersion {
		return nil, fmt.Errorf("policy schema version mismatch, got %d expect %d", pcy.GetSerialVersion(), SerialVersion)
	}
	return &ContainedPolicy{
		Policy:    pcy,
		Container: polc,
	}, nil
}

// ContainPolicy wraps the policy in a signed container.
// Use a nil key to skip signature.
func ContainPolicy(p *polio.Policy, key *rsa.PrivateKey) (*polio.PolicyContainer, error) {
	var signature []byte
	var err error
	if p.GetSerialVersion() != SerialVersion {
		return nil, fmt.Errorf("invalid policy schema version, got %d expected %d", p.GetSerialVersion(), SerialVersion)
	}
	rng := rand.Reader

	// Make a copy of the policy modified so that fields we don't want included
	// in the signature are zeroed out. These fields will be copied into the
	// container and then restored from there when the container is unwrapped.
	pmod := *p
	pmod.PolicyDate = ""
	pmod.PolicyRevision = ""
	pmod.PolicyMetadata = ""

	// Serialize using the Deterministic option to help ensure stability of byte
	// ordering over repeated serializations of the same Policy (at least for a
	// given executable). Currently this option only affects map key ordering,
	// and there are currently no maps in the Policy structure, but it doesn't
	// hurt to include this little bit of future proofing. In any case, stable
	// ordering requires careful control of element ordering in all slices in
	// structs to be serialized. For more information about byte ordering, see
	// https://developers.google.com/protocol-buffers/docs/encoding#implications
	// https://gist.github.com/kchristidis/39c8b310fd9da43d515c4394c3cd9510
	pbunData, err := proto.MarshalOptions{Deterministic: true}.Marshal(&pmod)
	if err != nil {
		return nil, fmt.Errorf("policy serialization failure: %v", err)
	}
	hashed := sha256.Sum256(pbunData)
	if key != nil {
		signature, err = rsa.SignPKCS1v15(rng, key, crypto.SHA256, hashed[:])
		if err != nil {
			return nil, err
		}
	}
	return &polio.PolicyContainer{
		ContainerVersion: ContainerVersion,
		Policy:           pbunData,
		PolicyVersion:    p.GetPolicyVersion(),
		PolicyDate:       p.PolicyDate,
		PolicyRevision:   p.PolicyRevision,
		PolicyMetadata:   p.PolicyMetadata,
		Signature:        signature,
	}, nil
}

// ReleasePolicy unwraps a policy, also checks schema version. If `pubkey` is
// non-nil checks signature.
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
