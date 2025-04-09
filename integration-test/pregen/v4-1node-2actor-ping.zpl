Note: two adapters: they can ping each other
Note: One node, one visa service: they can ping each other

define adapter as a device with cn

define A1 as adapter with cn:adapter1
define A2 as adapter with cn:adapter2
define Node as adapter with cn:node
define Vs as adapter with cn:'vs.zpr'

define A1Svc as a service with cn:adapter1
define A2Svc as a service with cn:adapter2
define PingableVs as a service with cn:'vs.zpr'
define PingableNode as a service with cn:node

allow A1 to access A2Svc
allow A2 to access A1Svc

allow Node to access PingableVs
allow Vs to access PingableNode




