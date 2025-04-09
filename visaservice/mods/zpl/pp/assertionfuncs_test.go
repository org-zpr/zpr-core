package pp_test

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/pp"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

func TestSimpleExternalFunctions(t *testing.T) {
	// Tests implementations of the simpler custom external functions (bitrate,
	// duration, host, port, port_set).
	yaml := `
        services:
          http:
            tcp: 80
        fish:
            trout:
                br1: 100kbps
                br2: 1kbps
                br3: 250kbps

            bass:
                br1: 100Mbps
                br2: 125kBps
                br3: 0.25Gbps @g1

        fowl:
            duck:
                cap1: 3600GB/h
                cap2: 1b/s @g2
                cap3: 108kB/10d # 10*24*60*60/8 = 108000
                dur1: 1s
                dur2: 60m
                dur3: .5d

        assertions:
            - desc: highest fish bitrate is 250 Mbps
              lang: internal
              assert: max(bitrate(fish.*.br*)) == 250e6

            - desc: br1 is 100 times br2 for every fish
              lang: internal
              assert: all([bitrate($f.br1) == 100 * bitrate($f.br2) for f in fish])

            - desc: there exists a duck capacity equivalent to 8 Gbps
              lang: internal
              assert: exists(bitrate(@@.duck.cap*) == 8_000_000_000)

            - desc: cap2 and cap3 are equivalent in terms of bitrate
              lang: internal
              assert: bitrate(fowl.@@.cap2) == bitrate(fowl.@@.cap3)

            - desc: dur1 is 1 second
              lang: internal
              assert: duration(@@.duck.dur1) == 1

            - desc: dur3 is 12 times dur2
              lang: internal
              assert: duration(@@.duck.dur3) == 12 * duration(@@.duck.dur2)

            - desc: duration in cap1 is 1 hr
              lang: internal
              assert: duration(@@.duck.cap1) == duration("1h")

            - desc: durations in cap1, cap2, and cap3 are 1h, 1s, and 10d
              lang: internal
              assert: all(duration([@@.duck.cap1, @@.duck.cap2, @@.duck.cap3]) == duration(["1h", "1s", "10d"]))

        neither:
            netaddr_type_things:
                a: somehost:12345
                b: 101.102.103.104:1234
                c: "[fc00:1001::]:443"

                assertions:
                    - desc: host works
                      lang: internal
                      assert: all(host([a, b, c]) == ["somehost", "101.102.103.104", "fc00:1001::"])

                    - desc: port works
                      lang: internal
                      assert: all(port([a, b, c]) == [12345, 1234, 443])

            port_type_things:
                a: 17
                b: 17,18
                c: 17,100-199, 2000 - 2009 , 65535
                assertions:
                    - desc: port set "a" includes 17 and not 18
                      lang: internal
                      assert: any(port_set(a) == 17) and not any(port_set(a) == 18)

                    - desc: port set "b" includes 17 and 18 and no others
                      lang: internal
                      assert: len(port_set(b)) == 2 and all(port_set(b) == [17, 18])

                    - desc: the union of port sets "a" and "b" is {17, 18}
                      lang: internal
                      assert: all(port_set(.'^[ab]$') == [17, 18])

                    - desc: port set "c" includes 112 ports
                      lang: internal
                      assert: len(port_set(c)) == 112

                    - desc: port set "c" includes ports 17, 117, and 65535
                      lang: internal
                      assert: count([$p == 17 or $p == 117 or $p == 65535 for p in port_set(c)]) == 3

                    - desc: port sets "a", "b", and "c" contain 113 ports altogether
                      lang: internal
                      assert: len(port_set(!assertions)) == 113
`

	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{Silent: true})
	require.NoError(t, err)

	yaml1 := strings.ReplaceAll(yaml, `dur3: .5d`, `dur3: 0.49d`)
	root1, err := yt.ReadYamlFromString(yaml1, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root1, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)
	require.Regexp(t, regexp.MustCompile(`dur3 is 12 times dur2`), err.Error())

	yaml2 := strings.ReplaceAll(yaml, `a: 17`, `a: 17-18`)
	root2, err := yt.ReadYamlFromString(yaml2, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root2, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)
	require.Regexp(t, regexp.MustCompile(`includes 17 and not 18`), err.Error())
}

func TestPotentialAccessFunction(t *testing.T) {
	yaml := `
        services:
          ssh:
            tcp: 22
          http:
            tcp: 80
          https:
            tcp: 443
          u443:
            udp: 443
          ping:
            icmp:
              type: request-response
              type_codes: 128, 129
        communications:
          systems:
            systemA:
              desc: system A
              components:
                comp0:
                  desc: system A, component 0
                  services: [ssh, ping]
                  provider:
                    - [ca0.x509.cn, eq, web.svc]
                  policies:
                    - desc: ssh
                      conditions:
                         - desc: admin only
                           attrs:
                              - [ds1.role, eq, admin]
                comp1:
                  desc: system A, component 1
                  services: [http, https, ping, ssh, u443]
                  provider:
                    - [ca0.x509.cn, eq, web.svc]
                  policies:
                    - desc: web
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, employee]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h
          assertions:
              - desc: 1. policy 0
                lang: internal
                assert: potential_access(@@.comp0.policies[0]) equals ["icmp128", "icmp129", "tcp22"]

              - desc: 2. component 0
                lang: internal
                assert: potential_access(@@.comp1) equals ["icmp128", "icmp129", "tcp22", "tcp443", "tcp80", "udp443"]
`
	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{Silent: true})
	require.NoError(t, err)
}

func TestPermittedAccessFunction(t *testing.T) {
	yaml := `
        services:
          ssh:
            tcp: 22
          http:
            tcp: 80
          https:
            tcp: 443
          ping:
            icmp:
              type: request-response
              type_codes: 128, 129

        communications:
          systems:
            systemA:
              desc: system A
              components:
                comp0:
                  desc: system A, comp 0
                  services: [ssh, ping]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh and ping ok if foo == x
                      conditions:
                         - desc: foo == x
                           attrs:
                              - [foo, eq, x]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h
                comp0_1:
                  desc: system A, comp 0_1
                  services: [ssh, http, https]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh and http ok (with constraints) if foo == x and bar == y
                      conditions:
                        - desc: foo == x and bar == y
                          attrs:
                            - [foo, eq, x]
                            - [bar, eq, y]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h

                comp1:
                  desc: system A, comp 1
                  services: [ssh, ping]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh and ping ok if foo ne x
                      conditions:
                         - desc: foo != x
                           attrs:
                              - [foo, ne, x]
                comp1_1:
                  desc: system A, comp 1_1
                  services: [http, https]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: http ok (with constraints) if foo has x and bar excludes y
                      conditions:
                        - desc: foo has x and bar excludes y
                          attrs:
                            - [foo, has, x]
                            - [bar, excludes, y]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h

          assertions:
              - desc: 1. single policy, no predicates
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: 2. single policy, simple condition predicate, pass
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo == x", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: 3. single policy, simple condition predicate, fail
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo != x", "") == [])

              - desc: 4. single policy, compound condition predicate with simple condition, pass
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo == x and bar == z", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: 5. single policy, compound condition predicate with simple condition, fail
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "bar == z and foo == y", "") == [])

              - desc: 6. single policy, simple condition and simple constraint, pass
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo == x", "max(bandwidth) <= 10Mbps") == ["icmp128", "icmp129", "tcp22"])

              - desc: 7. single policy, simple condition and simple constraint, fail on constraint
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo == x", "max(bandwidth) > 10Mbps") == [])

              - desc: 8. single policy, simple condition and compound constraint, pass
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo == x", "max(bandwidth) > 5Mbps and max(duration) == 1h") == ["icmp128", "icmp129", "tcp22"])

              - desc: 9. single policy, simple condition and compound constraint, fail on constraint
                lang: internal
                assert: all(permitted_access(@@.comp0.policies[0], "foo == x", "max(bandwidth) > 5Mbps and max(duration) <= 0.99h") == [])

              - desc: 10. single policy, compound condition predicate, pass
                lang: internal
                assert: all(permitted_access(@@.comp0_1.policies[0], "foo==x and bar eq y", "") == ["tcp22", "tcp443", "tcp80"])

              - desc: 11. single policy, compound condition predicate, fail
                lang: internal
                assert: all(permitted_access(@@.comp0_1.policies[0], "foo==x and bar eq z", "") == [])

              - desc: 12. single policy, simple condition predicate with compound condition, fail
                lang: internal
                assert: all(permitted_access(@@.comp0_1.policies[0], "foo == x", "") == [])

              - desc: 13. single policy, compound condition predicate with compound condition, pass
                lang: internal
                assert: all(permitted_access(@@.comp0_1.policies[0], "foo = x and bar = y", "") == ["tcp22", "tcp443", "tcp80"])

              - desc: 14. single policy, compound condition predicate with compound condition and compound constraint, pass
                lang: internal
                assert: all(permitted_access(@@.comp0_1.policies[0], "foo=x and bar=y", "max(bandwidth)>=20Mbps and max(duration)<=60m)") == ["tcp22", "tcp443", "tcp80"])

              - desc: 15. single policy, compound condition predicate with compound condition and compound constraint, fail on constraint
                lang: internal
                assert: all(permitted_access(@@.comp0_1.policies[0], "foo = x and bar = y", "max(bandwidth) != 20000kbps and max(duration) <= 60m)") == [])

              - desc: 16. single policy, simple condition predicate, simple ne condition, pass (ne)
                lang: internal
                assert: all(permitted_access(@@.comp1.policies[0], "foo != x", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: 17. single policy, simple condition predicate, simple ne condition, pass (eq)
                lang: internal
                assert: all(permitted_access(@@.comp1.policies[0], "foo == y", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: 18. single policy, simple condition predicate, simple ne condition, fail (eq)
                lang: internal
                assert: all(permitted_access(@@.comp1.policies[0], "foo == x", "") == [])

              - desc: 19. single policy, simple condition predicate, simple ne condition, fail (ne)
                lang: internal
                assert: all(permitted_access(@@.comp1.policies[0], "foo != y", "") == [])

              - desc: 20. single policy, compound condition predicate, pass (eq, eq)
                lang: internal
                assert: all(permitted_access(@@.comp1_1.policies[0], "foo = x and bar = z", "") == ["tcp443", "tcp80"])

              - desc: 21. single policy, compound condition predicate, pass (eq, eq, sets)
                lang: internal
                assert: all(permitted_access(@@.comp1_1.policies[0], "foo = a,b,x and bar = a,z", "") == ["tcp443", "tcp80"])

              - desc: 22. single policy, compound condition predicate, pass (has, excludes)
                lang: internal
                assert: all(permitted_access(@@.comp1_1.policies[0], "foo has x and bar excludes y", "") == ["tcp443", "tcp80"])

              - desc: 23. single policy, compound condition predicate, fail (eq, eq)
                lang: internal
                assert: all(permitted_access(@@.comp1_1.policies[0], "foo eq x and bar eq y", "") == [])

              - desc: 24. single policy, compound condition predicate, fail (excludes, excludes)
                lang: internal
                assert: all(permitted_access(@@.comp1_1.policies[0], "foo excludes x and bar excludes y", "") == [])

              - desc: 25. single policy, compound condition predicate, fail (has, has)
                lang: internal
                assert: all(permitted_access(@@.comp1_1.policies[0], "foo has x and bar has y", "") == [])

              - desc: 26. entire component, simple condition predicate, pass one policy
                lang: internal
                assert: all(permitted_access(@@.comp0, "foo eq x", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: 27. entire component(s), compound condition predicate, pass multiple policies
                lang: internal
                assert: all([permitted_access(comp, "foo eq x and bar eq y", "") equals ["icmp128", "icmp129", "tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: 28. entire component(s), compound condition predicate, simple constraint predicate, pass one policy
                lang: internal
                assert: all([permitted_access(comp, "foo eq x and bar eq y", "max(bandwidth) > 15Mbps") equals ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: 29. entire component(s), compound condition predicate, simple constraint predicate, pass multiple policies
                lang: internal
                assert: all([permitted_access(comp, "foo eq x and bar eq y", "max(bandwidth) > 5Mbps") equals ["icmp128", "icmp129", "tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: 30. entire component(s), compound condition predicate, simple constraint predicate, fail on constraint
                lang: internal
                assert: all([permitted_access(comp, "foo eq x and bar eq y", "max(duration) != 3600s") == [] for comp in @@."^comp0"])
`
	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{Silent: true})
	require.NoError(t, err)
}

func TestNonforbiddenAccessFunction(t *testing.T) {
	yaml := `
        services:
          ssh:
            tcp: 22
          http:
            tcp: 80
          https:
            tcp: 443
          ping:
            icmp:
              type: request-response
              type_codes: 128, 129
        communications:
          systems:
            systemA:
              desc: system A
              components:
                comp0:
                  desc: system A, comp 0
                  services: [ssh, ping]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh and ping ok if foo == x
                      conditions:
                         - desc: foo == x
                           attrs:
                              - [foo, eq, x]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h
                comp0_1:
                  desc: system A, comp 0_1
                  services: [http, https]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh and http ok (with constraints) if foo == x and bar == y
                      conditions:
                        - desc: foo == x and bar == y
                          attrs:
                            - [foo, eq, x]
                            - [bar, eq, y]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h
                comp0_2:
                  desc: system A, comp 0_2
                  services: [ssh]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh ok (with constraints) if foo == x and bar == y
                      conditions:
                        - desc: foo == x and bar == y
                          attrs:
                            - [foo, eq, x]
                            - [bar, eq, y]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h

                comp1:
                  desc: system A, comp 1
                  services: [ssh, ping]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: ssh and ping ok if foo ne x
                      conditions:
                         - desc: foo != x
                           attrs:
                              - [foo, ne, x]
                comp1_2:
                  desc: system A, comp 1_2
                  services: [http, https]
                  provider:
                    - [a, eq, b]
                  policies:
                    - desc: http ok (with constraints) if foo has x and bar excludes y
                      conditions:
                        - desc: foo has x and bar excludes y
                          attrs:
                            - [foo, has, x]
                            - [bar, excludes, y]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h

          assertions:
              - desc: single policy, no predicates
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, simple condition predicate, pass (relevant eq)
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "foo == x", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, simple condition predicate, pass (irrelevant eq)
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "bar == z", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, simple condition predicate, fail
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "foo != x", "") == [])

              - desc: single policy, simple condition predicate, pass (irrelevant excludes)
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "bar excludes z", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: all comp0 components, compound condition predicate, pass (relevant eq)
                lang: internal
                assert: all([nonforbidden_access(comp, "foo == x and bar == y", "") equals ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: all comp0 components, compound condition predicate, pass (irrelevant)
                lang: internal
                assert: all([nonforbidden_access(comp, "qux has z and baz excludes t", "") equals ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: single policy, simple condition and simple constraint, pass
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "foo == x", "max(bandwidth) >= 10Mbps") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, simple condition and simple constraint, fail on condition
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "foo != x", "max(bandwidth) >= 10Mbps") == [])

              - desc: single policy, simple condition and simple constraint, fail on constraint
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "foo == x", "max(bandwidth) < 10Mbps") == [])

              - desc: single policy, simple condition and simple constraint, pass (irrelevant condition)
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "bar == y", "max(bandwidth) >= 10Mbps") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, simple condition and simple constraint, fail on constraint (irrelevant condition)
                lang: internal
                assert: all(nonforbidden_access(@@.comp0.policies[0], "bar == y", "max(bandwidth) <= 9.999Mbps") == [])

              - desc: all comp1, compound condition predicate, pass (relevant eq)
                lang: internal
                assert: all([nonforbidden_access(comp, "foo==x and bar eq y", "") equals ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp1"])

              - desc: all comp1, compound condition predicate, pass (irrelevant)
                lang: internal
                assert: all([nonforbidden_access(comp, "qux has z", "") == ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp1"])

              - desc: all comp1, compound condition predicate, fail (ne)
                lang: internal
                assert: all([nonforbidden_access(comp, "bar ne y", "") == [] for comp in @@."^comp1"])

              - desc: all comp1, compound condition predicate, fail (ne, ne)
                lang: internal
                assert: all([nonforbidden_access(comp, "foo ne x and bar!=y", "") == [] for comp in @@."^comp1"])

              - desc: all comp1, compound condition predicate, simple constraint, pass
                lang: internal
                assert: all([nonforbidden_access(comp, "foo = x and bar = y", "max(duration)>=60m") equals ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp1"])

              - desc: all comp1, compound condition predicate, simple constraint, fail on condition
                lang: internal
                assert: all([nonforbidden_access(comp, "foo = x and bar = y", "max(duration)>60m") == [] for comp in @@."^comp1"])

              - desc: all comp 1, simple condition predicate, simple ne condition, pass (ne)
                lang: internal
                assert: all([nonforbidden_access(comp, "foo != x", "") equals ["icmp128", "icmp129", "tcp22"] for comp in @@."^comp1"])

              - desc: single policy, simple condition predicate, simple ne condition, pass (eq)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1.policies[0], "foo == y", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, simple condition predicate, simple ne condition, fail (eq)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1.policies[0], "foo == x", "") == [])

              - desc: single policy, simple condition predicate, simple ne condition, fail (ne)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1.policies[0], "foo != y", "") == ["icmp128", "icmp129", "tcp22"])

              - desc: single policy, compound condition predicate, pass (eq, eq)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo = x and bar = z", "") == ["tcp443", "tcp80"])

              - desc: single policy, compound condition predicate, pass (eq, omitted)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo = x", "") == ["tcp443", "tcp80"])

              - desc: single policy, compound condition predicate, pass (irrelevant)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "qux has z", "") == ["tcp443", "tcp80"])

              - desc: single policy, compound condition predicate, pass (eq, eq, sets)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo = a,x,b and bar = z,a", "") == ["tcp443", "tcp80"])

              - desc: single policy, compound condition predicate, pass (has, excludes)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo has x and bar excludes y", "") == ["tcp443", "tcp80"])

              - desc: single policy, compound condition predicate, fail (eq, eq)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo eq x and bar eq y", "") == [])

              - desc: single policy, compound condition predicate, fail (excludes, excludes)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo excludes x and bar excludes y", "") == [])

              - desc: single policy, compound condition predicate, fail (has, has)
                lang: internal
                assert: all(nonforbidden_access(@@.comp1_2.policies[0], "foo has x and bar has y", "") == [])

              - desc: entire component, simple condition predicate, pass one policy
                lang: internal
                assert: all([nonforbidden_access(comp, "foo eq x", "") equals ["icmp128", "icmp129", "tcp22", "tcp443", "tcp80"] for comp in @@."^comp1"])

              - desc: entire component, compound condition predicate, pass multiple policies
                lang: internal
                assert: all([nonforbidden_access(comp, "foo eq x and bar eq y", "") equals ["icmp128", "icmp129", "tcp22", "tcp443", "tcp80"] for comp in @@."^comp1"])

              - desc: entire component, compound condition predicate, simple condition predicate, pass one policy
                lang: internal
                assert: all([nonforbidden_access(comp, "foo eq x and bar eq y", "max(bandwidth) > 15Mbps") equals ["tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: entire component, compound condition predicate, simple condition predicate, pass multiple policies
                lang: internal
                assert: all([nonforbidden_access(comp, "foo=x and bar=y", "max(bandwidth)>5Mbps") equals ["icmp128", "icmp129", "tcp22", "tcp443", "tcp80"] for comp in @@."^comp0"])

              - desc: entire component, compound condition predicate, simple condition predicate, fail
                lang: internal
                assert: all([nonforbidden_access(comp, "foo eq x and bar eq y", "max(duration) > 60m") == [] for comp in @@."^comp0"])
`
	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{Silent: true})
	require.NoError(t, err)
}

// An in-memory DataSourceProxy implementation for testing.
type testDataSourceProxy struct {
	attrs map[string]map[string]string // actor ID -> attr name -> attr value
}

func (p *testDataSourceProxy) ActorIds(exprs []pp.AttributeExpression) ([]string, error) {
	has := func(val1, val2 string) bool {
		for _, v := range strings.Split(val1, ",") {
			if v == val2 {
				return true
			}
		}
		return false
	}

	idSet := make(map[string]bool) // ID -> true

idLoop:
	for id, attrMap := range p.attrs {
		allExprsSatisfied := true
		for _, expr := range exprs {
			if attrVal, defined := attrMap[expr.Name]; !defined {
				continue idLoop
			} else {
				var exprSatisfied bool
				switch expr.Operator {
				case "eq":
					exprSatisfied = attrVal == expr.Value
				case "ne":
					exprSatisfied = attrVal != expr.Value
				case "has":
					exprSatisfied = has(attrVal, expr.Value)
				case "excludes":
					exprSatisfied = !has(attrVal, expr.Value)
				default:
					panic(fmt.Sprintf("invalid operator: %q", expr.Operator))
				}
				if !exprSatisfied {
					allExprsSatisfied = false
					break
				}
			}
		}
		if allExprsSatisfied {
			idSet[id] = true
		}
	}

	results := make([]string, 0, len(idSet))
	for id, _ := range idSet {
		results = append(results, id)
	}
	sort.Strings(results)
	return results, nil
}

func TestPermittedAccessCountsFunction(t *testing.T) {
	yaml := `
        services:
          ssh:
            tcp: 22
          http:
            tcp: 80
          https:
            tcp: 443
          u54321:
            udp: 54321
          t12345:
            tcp: 12345

        communications:
          hierarchy:
            - divisions
            - regions
          divisions:
            divA:
              desc: division A
              components:
                compA0:
                  desc: division A component 0
                  services: [https]
                  policies:
                    - desc: all employees get https access
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, user]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 2h
                    - desc: admin gets https
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds0.roles, has, admin]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h
                compA0_1:
                  desc: division A component 0_1
                  services: [ssh]
                  policies:
                    - desc: admin gets ssh access
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds0.roles, has, admin]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h

                compA1:
                  desc: division A component 1
                  servoces: [ssh]
                  policies:
                    - desc: admin gets access to everything
                      conditions:
                         - desc: admin only
                           attrs:
                              - [ds0.roles, has, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps
                compA1_1:
                  desc: division A component 1_1
                  services: [https]
                  policies:
                    - desc: all employees get https access
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, user]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h
                    - desc: admin gets access to everything
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds0.roles, has, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps
                compA1_2:
                  desc: division A component 1_2
                  services: [u54321]
                  policies:
                    - desc: specialudp
                      conditions:
                          - desc: non-marketing employees only
                            attrs:
                              - [ds0.roles, has, user]
                              - [ds1.department, ne, marketing]
                      constraints:
                        duration: 4h
                    - desc: admin gets access to everything
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds0.roles, has, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps

              regions:
                regX:
                  desc: division A region X
                  services:
                    compX0:
                      desc: division A region X component 0
                      services: [t12345]
                      policies:
                        - desc: admin users get high-bandwidth, long-duration access
                          conditions:
                             - desc: admin users only
                               attrs:
                                  - [ds0.roles, has, admin]
                          constraints:
                            bandwidth: 100Mbps
                            duration: 1h
                        - desc: non-admin users get low-bandwidth, short-duration access
                          conditions:
                             - desc: non-admin users
                               attrs:
                                  - [ds0.roles, has, user]
                                  - [ds0.roles, excludes, admin]
                          constraints:
                            bandwidth: 1Mbps
                            duration: 10m

          assertions:
            - desc: single policy, no predicates
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "", "") == ["tcp443=5"])

            - desc: single policy, simple condition predicate, pass
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has user", "") == ["tcp443=5"])

            - desc: single policy, simple condition predicate, fail
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has other", "") == [])

            - desc: single policy, compound condition predicate with simple condition, pass
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has admin and ds0.role has user", "") == ["tcp443=3"])

            - desc: single policy, compound condition predicate with simple condition, fail
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has admin and ds0.role excludes user", "") == [])

            - desc: single policy, simple condition and simple constraint, pass
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has user", "max(bandwidth) <= 10Mbps") == ["tcp443=5"])

            - desc: single policy, simple condition and simple constraint, fail on constraint
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has user", "max(bandwidth) > 10Mbps") == [])

            - desc: single policy, simple condition and compound constraint, pass
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has user", "max(bandwidth) > 10Mbps and max(duration) == 2h") == ["tcp443=5"])

            - desc: single policy, simple condition and compound constraint, fail on constraint
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[0], "ds0.role has user", "max(bandwidth) < 10Mbps and max(duration) == 2h") == [])

            - desc: all of compA, compound condition predicate, pass 1
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.role has user and ds1.department == marketing", "") == ["udp54321=1"] for comp in @@."^compA"])

            - desc: all of compA, compound condition predicate, pass 2
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.role has user and ds1.department != marketing", "") == ["udp54321=2"] for comp in @@."^compA"])

            - desc: single policy, simple condition predicate with compound condition, fail
              lang: internal
              assert: all(permitted_access_counts(@@.compA0.policies[1], "ds0.role has user", "") == [])

            - desc: entire component, no condition predicate, no constraint predicate
              lang: internal
              assert: all([permitted_access_counts(comp, "", "") equals ["tcp22=3", "tcp443=5"] for comp in @@."^compA"])

            - desc: entire component, simple condition predicate, pass one policy (1)
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.roles has admin", "") equals ["tcp22=3", "tcp443=3"] for comp in @@."^compA"])

            - desc: entire component, compound condition predicate, pass one policy (2)
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.roles has user and ds0.roles has admin", "") equals ["tcp22=3", "tcp443=3"] for comp in @@."^compA"])

            - desc: entire component, compound condition predicate, pass multiple policies
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.roles has user and ds1.department eq finance", "") equals ["tcp443=1", "udp54321=1"] for comp in @@."^compA1"])

            - desc: entire component, pass one policy, fail one on constraints (1)
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.roles has admin", "max(duration) == 1h") == ["tcp12345=3"] for comp in @@."^compX"])

            - desc: entire component, pass one policy, fail one on constraints (2)
              lang: internal
              assert: all([permitted_access_counts(comp, "ds0.rules has user and ds0.roles excludes admin", "max(duration) == 10m") == ["tcp12345=3"] for comp in @@."^compX"])
`
	dsProxies := map[string]pp.DataSourceProxy{
		"ds0": &testDataSourceProxy{map[string]map[string]string{
			"id0001": map[string]string{"name": "admin1", "roles": "user,admin"},
			"id0002": map[string]string{"name": "admin2", "roles": "user,admin"},
			"id0003": map[string]string{"name": "admin3", "roles": "user,admin"},
			"id0004": map[string]string{"name": "peon4", "roles": "user"},
			"id0005": map[string]string{"name": "peon5", "roles": "user"}}},
		"ds1": &testDataSourceProxy{map[string]map[string]string{
			"id0001": map[string]string{"name": "admin1", "department": "engineering", "something": "else"},
			"id0002": map[string]string{"name": "admin2", "department": "marketing"},
			"id0004": map[string]string{"name": "peon4", "department": "finance"}}},
	}

	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, dsProxies, os.Stderr, &pp.PreprocessOpts{Silent: true, DynamicAsserts: true})
	require.NoError(t, err)
}
