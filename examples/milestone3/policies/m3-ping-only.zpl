Note: Allow a specific agent to ping another specific agent.
Note: Since we don't yet authenticate users, this policy is expressed using endpoints.


define adapter as a device with cn

define ZServicePingable as a service with cn:'service.zpr.org'

allow cn:'client.zpr.org' adapter to access ZServicePingable


