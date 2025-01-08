Note: Allow a specific agent to ping another specific agent.
Note: Since we don't yet authenticate users, this policy is expressed using endpoints.


define adapter as an endpoint with zpr.adapter.cn

define ZServicePingable as a service with zpr.adapter.cn:service.zpr.org

allow adapter with zpr.adapter.cn:client.zpr.org to access ZServicePingable

