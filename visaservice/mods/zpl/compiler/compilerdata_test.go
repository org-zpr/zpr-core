package compiler_test

//
// These are known good policies included here so that I can be sure I haven't broken things.
//

const GoodPolicy1 = `
zpl_format: 2

#main:
#policy_version: 1
#policy_date: "2020-11-25T00:00:00Z"

services:
  auth:
    tcp: 5001
  http:
    tcp: 80

zpr:
  nodes:
    n0:
      key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
      provider:
        - [ca0.x509.cn, eq, n0.internal]
      address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
  datasources:
    ca0:
      api: validation/1
      authority:
        encoding: pem
        cert_data: $import[ca0-cert.pem]
    simplev:
      api: validation/1; query/1
      endpoint:
        provider:
          - [ca0.x509.cn, eq, ca-vdator.internal]
        address: "fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59"
        services: [auth]
        tls_domain: auth0.spacelaser.net
        tls_cert:
          encoding: pem
          cert_data: $import[simplev-cert.pem]
  visaservice:
    provider:
      - [ca0.x509.cn, eq, vs.internal]
    admin_attrs:
      - [simplev.role, zpradmin]

communications:
  systems:
    mathiasland:
      desc: mathiasland
      components:
        rfc.spacelaser.net:
          desc: rfc
          provider:
            - [ca0.x509.cn, eq, rfc.svc]
          address: "fc00:3001:26f4:851a:7f0:e98d:1373:32d"
          services: [http]
          policies:
            - desc: anyone using simplev can access
              conditions:
                - desc: any loggged in via simplev
                  attrs:
                    - [zpr.authority, eq, simplev]
            - desc: anyone using internal can access
              conditions:
                - desc: any loggged in via ca0
                  attrs:
                    - [zpr.authority, eq, ca0]
`

const GoodPolicy2 = `
zpl_format: 2

main:
  policy_version: 1
  policy_date: "2020-11-25T00:00:00Z"

services:
  auth:
    tcp: 5001

zpr:
  nodes:
    n0:
      key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
      provider:
        - [ca0.x509.cn, eq, n0.internal]
      address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
    n1:
      key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950053"
      provider:
        - [ca0.x509.cn, eq, n1.internal]
      address: "fc00:3001:c564:251e:e13b:2efd:7e7a:da7d"
      interfaces:
        i0:
          netaddr: "n1.spacelaser.net:5000"

  datasources:
    ca0:
      api: validation/1
      authority:
        encoding: pem
        cert_data: $import[ca0-cert.pem]
    simplev:
      api: validation/1; query/1
      endpoint:
        provider:
          - [ca0.x509.cn, eq, ca-vdator.internal]
        address: "fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59"
        services: [auth]
        tls_domain: auth0.spacelaser.net
        tls_cert:
          encoding: pem
          cert_data: $import[simplev-cert.pem]

  visaservice:
    dock: n0
    provider:
      - [ca0.x509.cn, eq, vs.internal]
    admin_attrs:
      - [simplev.role, zpradmin]

communications:
  systems:
    mathiasland:
      desc: mathiasland
`

const GoodPolicySpaceLaser = `
zpl_format: 2


main:
  policy_version: 4
  policy_date: "2020-10-22T12:32:00Z"

services:
  auth:
    tcp: 5001
  ping:
    icmp:
      type: request-response
      type_codes: 128, 129
  time:
    udp: 123
  elastic:
    tcp: 9200
  logship:
    tcp: 5044
  dns:
    udp: 53
  grafanaui:
    tcp: 3000
  promui:
    tcp: 9090
  prom:
    tcp: 2112
  http:
    tcp: 80
  https:
    tcp: 443
  gitssh:
    tcp: 8022
  ircd:
    tcp: 6697




defines:
  monitor.attrs: # the monitor service provider identity
    - [simplev.scheme, eq, ca-rsa-v1]
    - [zpr.addr, eq, fc00:3001::fa57:abcf:9895:6469]

  admin_can_ping:
    desc: admin can ping policy (apply only to ping service)
    services: [ping]
    conditions:
      - desc: must be admin blessed by simplev
        attrs:
          - [simplev.zpradmin, eq, t]

zpr:

  globals:
    max_connections: 100
    max_connections_per_dock: 10
    max_connections_per_actor: 3

  nodes:
    defines:
      prometheus.policy:
        desc: monitor host can access prometheus stats (should apply only to prom service)
        services: [prom]
        conditions:
          - desc: allow from monitor
            attrs:
              $monitor.attrs:

    n0:
      key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
      provider:
        - [zpr.addr, eq, "fc00:3001:fd2c:45d:d9b:c18f:f18d:738f"]
        - [zpr.authority, eq, simplev]
      address: "fc00:3001:fd2c:45d:d9b:c18f:f18d:738f"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
      services: [ping, prom]
      policies:
        - $admin_can_ping
        - $prometheus.policy

    n1:
      key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950053"
      provider:
        - [zpr.addr, eq, "fc00:3001:ab73:1ec8:4242:c325:69e:c085"]
        - [zpr.authority, eq, simplev]
      address: "fc00:3001:ab73:1ec8:4242:c325:69e:c085"
      interfaces:
        i0:
          netaddr: "n1.spacelaser.net:5000"
      services: [ping, prom]
      policies:
        - $admin_can_ping
        - $prometheus.policy

  visaservice:
    dock: n0
    provider:
      - [ca0.x509.cn, eq, vs.internal]
    admin_attrs:
      - [simplev.zpradmin, t]

  addresses:
    tether_net: "fc00:3002::0/32"
    zpr_net: "fc00:3001::0/32"

  datasources:
    ca0:
      api: validation/1
      authority:
        encoding: pem
        cert_data: $import[ca0-cert.pem]
    simplev:
      api: validation/1; query/1
      endpoint:
        provider:
          - [ca0.x509.cn, eq, auth0.spacelaser.net]
        address: "fc00:3001:9667:3c6d:af0e:2cb6:d0e4:f8f6"
        services: [auth, ping]
        tls_domain: auth0.spacelaser.net
        tls_cert:
          encoding: pem
          cert_data: $import[simplev-cert.pem]
        policies:
          - desc: admin can ping
            services: [ping]
            conditions:
              - desc: must be admin blessed by simplev
                attrs:
                  - [simplev.zpradmin, eq, t]


# The hierarchy is so far:
#
#  NETWORK->                SYSTEM:spacelaser
#                                   |
#                    +--------------+-------------+--------------------------+
#                    |                            |                          |
#                    |                            |                          |
#  DIVISION->  SYSTEM:zpr nodes               SYSTEM:zpr core            SYSTEM:resources
#                     |                            |                          |
#                     |- SVC:n0                    |- SVC:time                |- SVC:hello
#                     |- SVC:n1                    |- SVC:logs                |- SVC:ncloud
#                     |- SVC:zpr admin             |- SVC:monitor
#                                                  |- SVC:dns
#                                                  |- SCV:auth



communications:
  hierarchy:
    - networks
    - divisions

  networks: # my hierarchy term, is-a list of 'system'
    spacelaser:
      desc: spacelaser
      defines:
        permit_all_net_users:
          desc: allow netusers access
          conditions:
            - desc: check for netuser role
              attrs:
                - [simplev.netuser, eq, t]
        permit_all_domain_users:
          desc: allow ai domain users access
          conditions:
            - desc: check for domain user
              attrs:
                - [simplev.google-openid.domain, eq, appliedinvention.com]
        netuser_can_ping:
          desc: (policy) netuser can ping (how to restrict to one service)
          services: [ping]
          conditions:
            - desc: must be netuser
              attrs:
                - [simplev.netuser, eq, t]

      defaults:
        constraints:
          desc: max bandwidth of 10Mbps # applies to every policy where a constraint is not specified.
          value:
              bandwidth: 10Mbps

      assertions:
        - desc: visa duration not to exceed 8h
          lang: internal
          assert: all(duration(@@.policies[*].constraints.duration) <= duration("8h"))

      divisions: # my hierarchy tag, is-a list of child 'system' blocks
        zcore:
          desc: zpr core system
          components:
            time.service:
              desc: time service
              provider:
                - [simplev.scheme, eq, ca-rsa-v1]
                - [zpr.addr, eq, "fc00:3001::9d24:62e8:6d72:3e66"]
              address: "fc00:3001::9d24:62e8:6d72:3e66"
              services: [time, ping]
              policies:
                - desc: access to time service
                  services: [time]
                  conditions:
                    - desc: allow from nodes
                      attrs:
                        - [zpr.role, eq, node]
                - $admin_can_ping
                - $netuser_can_ping

            log.service:
              desc: log database service for recieving logs
              services: [logship, elastic, ping]
              provider:
                - [simplev.scheme, eq, ca-rsa-v1]
                - [zpr.addr, eq, "fc00:3001::9748:667e:fc50:1bca"]
              address: "fc00:3001::9748:667e:fc50:1bca"
              policies:
                - desc: nodes send in logs
                  services: [logship]
                  conditions:
                    - desc: allow from nodes
                      attrs:
                        - [zpr.role, eq, node]
                - desc: grafana queries elasticsearch
                  services: [elastic]
                  conditions:
                    - desc: allow from monitor
                      attrs:
                        - [zpr.addr, eq, "fc00:3001::fa57:abcf:9895:6469"]
                - desc: devs query elasticsearch
                  services: [elastic]
                  conditions:
                    - desc: allow based on simplev role
                      attrs:
                        - [simplev.elasticOK, eq, 1]
                  constraints:
                    duration: 4h
                - $admin_can_ping
                - $netuser_can_ping

            monitorsvc:
              desc: monitor service (grafana and prometheus)
              services: [grafanaui, promui, ping]
              provider:
                $monitor.attrs:
              address: "fc00:3001::fa57:abcf:9895:6469"
              policies:
                - desc: devs can access grafana and prometheus
                  services: [grafanaui, promui]
                  conditions:
                    - desc: allow based on simplev role
                      attrs:
                        - [simplev.grafanaOK, eq, 1]
                - $admin_can_ping
                - $netuser_can_ping

            dns.service:
              desc: dns service
              services: [dns]
              provider:
                - [zpr.addr, eq, "fc00:3001::dacf:b86b:10cb:4ecd"]
                - [simplev.scheme, eq, ca-v1-sha256]
              address: "fc00:3001::dacf:b86b:10cb:4ecd"
              policies:
                - $permit_all_net_users
                - $permit_all_domain_users
                - desc: entire zpr net can access dns (internal)
                  conditions:
                    - desc: allow if authd by internal cert
                      attrs:
                        - [zpr.authority, eq, ca0]

            dns.service.ping:
              desc: dns service ping
              services: [ping]
              provider:
                - [zpr.addr, eq, "fc00:3001::dacf:b86b:10cb:4ecd"]
                - [simplev.scheme, eq, ca-v1-sha256]
              address: "fc00:3001::dacf:b86b:10cb:4ecd"
              policies:
                - $admin_can_ping
                - $netuser_can_ping

        zrsrc:
          desc: network resources system
          components:
            hello.service:
              desc: hello (svc0)
              services: [http, https, gitssh, ircd]
              provider:
                - [zpr.addr, eq, "fc00:3001:db24:6020:450:e816:a450:2056"]
                - [zpr.authority, eq, simplev]
                - [simplev.scheme, eq, ca-v1-sha256]
              address: "fc00:3001:db24:6020:450:e816:a450:2056"
              policies:
                - $permit_all_net_users
                - $permit_all_domain_users

            ncloud.service:
              desc: ncloud (svc1)
              services: [http]
              provider:
                - [zpr.authority, eq, simplev]
                - [zpr.addr, eq, "fc00:3001:e950:d242:a363:85c1:775a:a601"]
              address: "fc00:3001:e950:d242:a363:85c1:775a:a601"
              policies:
                - $permit_all_net_users
                - $permit_all_domain_users
`
