package pp_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/pp"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

func TestExplicitServiceDefaults(t *testing.T) {
	yaml := `
        zpl_format: 2
        communications:
          systems:
            sys0:
              desc: defaults for both auth and provider
              defaults:
                auth:
                  desc: default auth
                  value:
                    api: api0
                provider:
                  desc: default provider
                  value:
                    - [pkey0, pval0]
              components:
                svc00:
                  desc: no defaults
                  auth:
                    api: api0_0
                  provider:
                    - [pkey0_0, pval0_0]
                svc01:
                  desc: auth defaulted
                  provider:
                    - [pkey0_1, pval0_1]
                svc02:
                  desc: provider defaulted
                  auth:
                    api: api0_2
                svc03:
                  desc: provider and auth defaulted
              systems:
                sys00:
                  desc: overriding default for auth only
                  defaults:
                    auth:
                      desc: default auth
                      value:
                        api: api00
                  components:
                    svc000:
                      desc: auth defaulted
                      provider:
                        - [pkey00_0, pval00_0]
                    svc001:
                      desc: provider and auth defaulted
            sys1:
              desc: no overriding defaults
              components:
                svc10:
                  desc: provider defaulted
                  auth:
                    api:
                      api1_0
`
	root0, err := yt.ReadYamlFromString(yaml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefaults(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc00.auth.api$api0_0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc00.provider[0][0]$pkey0_0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc01.auth.api$api0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc01.provider[0][0]$pkey0_1`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc02.auth.api$api0_2`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc02.provider[0][0]$pkey0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc03.auth.api$api0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.components.svc03.provider[0][0]$pkey0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.systems.sys00.components.svc000.auth.api$api00`))
	require.True(t, pathExists(root1, `communications.systems.sys0.systems.sys00.components.svc000.provider[0][0]$pkey00_0`))
	require.True(t, pathExists(root1, `communications.systems.sys0.systems.sys00.components.svc001.auth.api$api00`))
	require.True(t, pathExists(root1, `communications.systems.sys0.systems.sys00.components.svc001.provider[0][0]$pkey0`))
	require.True(t, pathExists(root1, `communications.systems.sys1.components.svc10.auth.api$api1_0`))
	require.False(t, pathExists(root1, `communications.systems.sys1.components.svc10.provider`))
}

func TestExplicitPolicyDefaults(t *testing.T) {
	yaml := `
        zpl_format: 2
        communications:
          hierarchy:
            - divisions
            - regions
          divisions:
            div0:
              desc: defaults for all policy keys
              defaults:
                scope:
                  desc: default scope
                  value:
                    - tcp: 10
                conditions:
                  desc: default conditions
                  value:
                    desc: ...
                    attrs:
                        - [key0, val0]
                constraints:
                  desc: default constraints
                  value:
                    bandwidth: 10Mbps
              components:
                svc00:
                  desc: ...
                  policies:
                    - desc: everything defaulted
                    - desc: conditions and constraints defaulted
                      scope:
                        - tcp: 100
                svc01:
                  desc: ...
                  policies:
                    - desc: constraints defaulted
                      scope:
                        - tcp: 101
                      conditions:
                        desc: ...
                        attrs:
                          - [key0_1a, val0_1a]
                    - desc: nothing defaulted
                      scope:
                        - tcp: 1011
                      conditions:
                        desc: ...
                        attrs:
                          - [key0_1b, cval0_1b]
                      constraints:
                        bandwidth: 101Mbps
              regions:
                reg00:
                  desc: overrides default for scope only
                  defaults:
                    scope:
                      desc: default scope
                      value:
                        - tcp: 1000
                  components:
                    svc000:
                      policies:
                        - desc: everything defaulted
                        - desc: conditions and constraints defaulted
                          scope:
                            - tcp: 1001
            div1:
              desc: no overriding defaults
              components:
                svc10:
                  desc: ...
                  policies:
                    - desc: conditions and constraints defaulted
                      scope:
                        - tcp: 10000
`
	root0, err := yt.ReadYamlFromString(yaml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefaults(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[0].scope[0].tcp$10`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[0].conditions.attrs[0][0]$key0`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[0].constraints.bandwidth$10Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[1].scope[0].tcp$100`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[1].conditions.attrs[0][0]$key0`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[1].constraints.bandwidth$10Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[0].scope[0].tcp$101`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[0].conditions.attrs[0][0]$key0_1a`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[0].constraints.bandwidth$10Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[1].scope[0].tcp$1011`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[1].conditions.attrs[0][0]$key0_1b`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[1].constraints.bandwidth$101Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[0].scope[0].tcp$1000`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[0].conditions.attrs[0][0]$key0`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[0].constraints.bandwidth$10Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[1].scope[0].tcp$1001`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[1].conditions.attrs[0][0]$key0`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[1].constraints.bandwidth$10Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div1.components.svc10.policies[0].scope[0].tcp$10000`))
	require.False(t, pathExists(root1, `communications.divisions.div1.components.svc10.policies[0].conditions`))
	require.False(t, pathExists(root1, `communications.divisions.div1.components.svc10.policies[0].constraints`))
}

func TestImplicitPolicyDefaults(t *testing.T) {
	yaml := `
        zpl_format: 2
        communications:
          hierarchy:
            - divisions
            - regions
          divisions:
            div0:
              desc: ...
              components:
                svc00:
                  desc: no implicit defaults for policy keys
                  policies:
                    - desc: everything defaulted
                    - desc: just scope defined
                      scope:
                        - tcp: 1000
                svc01:
                  desc: implicit defaults for all policy keys
                  scope:
                    - tcp: 101
                  conditions:
                    desc: ...
                    attrs:
                      - [key01, val01]
                  constraints:
                    bandwidth: 101Mbps
                  policies:
                    - desc: everything defaulted
                    - desc: just scope defined
                      scope:
                        - tcp: 1010
              regions:
                reg00:
                  desc: ...
                  components:
                    svc000:
                      desc: implicit default for scope only
                      scope:
                        - tcp: 10000
                      policies:
                        - desc: everything defaulted
            div1:
              desc: ...
              components:
                svc10:
                  desc: implicit default for constraints only
                  constraints:
                    bandwidth: 110Mbps
                  policies:
                    - desc: conditions and constraints defaulted
                      scope:
                        - tcp: 1100
`
	root0, err := yt.ReadYamlFromString(yaml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefaults(root0)
	require.NoError(t, err)

	require.False(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[0].scope[0]`))
	require.False(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[0].conditions`))
	require.False(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[0].constraints`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[1].scope[0].tcp$1000`))
	require.False(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[1].conditions`))
	require.False(t, pathExists(root1, `communications.divisions.div0.components.svc00.policies[1].constraints`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[0].scope[0].tcp$101`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[0].conditions.attrs[0][0]$key01`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[0].constraints.bandwidth$101Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[1].scope[0].tcp$1010`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[1].conditions.attrs[0][0]$key01`))
	require.True(t, pathExists(root1, `communications.divisions.div0.components.svc01.policies[1].constraints.bandwidth$101Mbps`))
	require.True(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[0].scope[0].tcp$10000`))
	require.False(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[0].conditions`))
	require.False(t, pathExists(root1, `communications.divisions.div0.regions.reg00.components.svc000.policies[0].constraints`))
	require.True(t, pathExists(root1, `communications.divisions.div1.components.svc10.policies[0].scope[0].tcp$1100`))
	require.False(t, pathExists(root1, `communications.divisions.div1.components.svc10.policies[0].conditions`))
	require.True(t, pathExists(root1, `communications.divisions.div1.components.svc10.policies[0].constraints.bandwidth$110Mbps`))
}
