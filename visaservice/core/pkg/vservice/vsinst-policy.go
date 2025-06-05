package vservice

import (
	"time"

	"zpr.org/vs/pkg/policy"
)

// GetPolicyAndMatcher returns the current policy details.
func (vs *VSInst) getPolicyMatcherConfig() (*policy.Policy, *policy.Matcher, uint64) {
	vs.plcy.RLock()
	defer vs.plcy.RUnlock()
	return vs.plcy.p, vs.plcy.matcher, vs.plcy.cid
}

func (vs *VSInst) getPolicyMatcherConfigHoldingLock() (*policy.Policy, *policy.Matcher, uint64) {
	return vs.plcy.p, vs.plcy.matcher, vs.plcy.cid
}

func (vs *VSInst) getPolicy() *policy.Policy {
	vs.plcy.RLock()
	defer vs.plcy.RUnlock()
	return vs.plcy.p
}

// For the visa service calling `InstallPolicy` performs the configuration activation.
// This function here just checks to make sure that the `configID` passed matches the
// one we have in our state.
//
// deactivates all other configurations
// implementation of policy.PolicyListener
func (vs *VSInst) ActivateConfiguration(configID uint64, _ byte) {
	vs.plcy.RLock()
	defer vs.plcy.RUnlock()
	if configID != vs.plcy.cid {
		vs.log.Error("activating configuration does not match state", "activating", configID, "has_configuration", vs.plcy.cid)
	}
}

// When a visa service gets a new policy, it needs all the nodes to
// re-up their configurations by re-authing themselves.
//
// For the node directly attached that is pretty easy.
//
// For others, we need to send an announcement which will trigger the nodes
// to make a visa service call, which will require a visa.
//
// Other things that happen when a new policy is installed (but not inside this function):
//   - renew the visa-service visas.
//   - cancel all the old policy visas.
//   - ensure all actors are still ok to connect.
//
// must install the policy under the given configuration.
// implementation of policy.PolicyListener
func (vs *VSInst) InstallPolicy(configID uint64, _ byte, pol *policy.Policy) error {

	vs.log.Info("installing policy to auth service")
	vs.authr.InstallPolicy(configID, 0, pol)

	vs.plcy.Lock()

	vs.log.Debug("new policy arrives for install")
	var prevConfig uint64
	if p, _, cid := vs.getPolicyMatcherConfigHoldingLock(); p != nil {
		prevConfig = cid
	}

	m, err := policy.NewMatcher(pol.ExportBundle(), configID, vs.log)
	if err != nil {
		vs.log.WithError(err).Error("failed to create matcher")
		vs.log.Error("policy install failed")
		vs.plcy.Unlock()
		return err
	}

	vs.plcy.p = pol
	vs.plcy.matcher = m
	vs.plcy.cid = configID

	vs.log.Info("new policy installed", "version", pol.Version(), "empty", pol.IsEmpty(), "prevConfig", prevConfig, "newConfig", configID)
	vs.plcy.Unlock()

	if (prevConfig > policy.InitialConfiguration) && (prevConfig != configID) {
		// Config has updated!
		vs.renewEssentialVisasForCurrentConfig(configID, pol.VersionNumber())
		vs.log.Info("configuration deprecated", "old_configuration", prevConfig)
		vs.cfgRemoves.Lock()
		vs.cfgRemoves.removes = append(vs.cfgRemoves.removes, &configRemoval{
			config:  prevConfig,
			removal: time.Now(),
		})
		vs.cfgRemoves.Unlock()
	}

	return vs.installPolicyWithVisasForNodes(pol, configID)
}
