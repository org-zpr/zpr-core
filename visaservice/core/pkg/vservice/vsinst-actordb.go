package vservice

import (
	"zpr.org/vs/pkg/actor"
	"zpr.org/vsx/polio"
)

// Callback function for adb/actordb
func (vs *VSInst) HandleDBActorAdded(agnt *actor.Actor) {
	pp, _, curConfig := vs.getPolicyMatcherConfig()

	if curConfig != agnt.GetConfigID() {
		// Not sure yet if this is an issue, so will log it.
		vs.log.Warn("actor added with different config id", "actor_config_id", agnt.GetConfigID(), "current_config", curConfig)
	}

	svcAddr, hasAddr := agnt.GetZPRID()
	if !hasAddr {
		return // no address, no service!
	}

	for _, serviceName := range agnt.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			if psvc.Type == polio.SvcT_SVCT_AUTH {
				err := vs.authr.AddDatasourceProvider(serviceName, svcAddr, curConfig)
				if err != nil {
					vs.log.WithError(err).Error("failed to add auth service", "service_name", serviceName)
				} else {
					vs.log.Info("service added", "service", serviceName, "address", svcAddr)
				}
			}
		}
	}
}

// Callback function for adb/actordb
func (vs *VSInst) HandleDBActorRemoved(agnt *actor.Actor) {
	pp, _, curConfig := vs.getPolicyMatcherConfig()
	if curConfig != agnt.GetConfigID() {
		vs.log.Warn("host-remove with different configuration", "actor_config_id", agnt.GetConfigID(), "current_config", curConfig)
	}
	for _, serviceName := range agnt.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			if psvc.Type == polio.SvcT_SVCT_AUTH {
				if vs.authr.RemoveServiceByPrefix(psvc.GetPrefix()) > 0 {
					vs.log.Info("host_removed", "lost_service", serviceName)
				}
			}
		}
	}
}
