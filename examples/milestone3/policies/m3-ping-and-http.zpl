Note: Allow a specific adapter to host a service and allow
Note: another adapter to access it.
Note: Since we don't yet authenticate users, this policy is expressed using endpoints.


define adapter as a device with cn
define GoldenClient as an adapter with cn:'client.zpr.org'

define ZServicePingable as a service with cn:'service.zpr.org'
define ZWebService as a service with cn:'service.zpr.org'

allow GoldenClient to access ZServicePingable
allow GoldenClient to access ZWebService


