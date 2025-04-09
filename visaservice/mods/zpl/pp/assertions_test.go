package pp_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/pp"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

// TODO Change standard-language tests to reflect new components/services.
// TODO Add standard-language tests that use service IDs instead of explicit protocols and ports.

func TestBasicInternalAssertionLanguageFunctionality(t *testing.T) {
	yaml := `
        services:
          empty:
            tcp: 1
        fish:
            one:
                red: 1
                blue: 2

            two:
                red: 17
                blue: 42
                green: 99

            three:
                red: 5
                blue: -1

            four:
                - green: 50

            assertions:
                - desc: all red must be odd
                  lang: internal
                  assert: all(.*.red % 2 == 1)

                - desc: there can be only one level-2 green
                  lang: internal
                  assert: len(.*.green$) == 1

                - desc: there must be at least two greens
                  lang: internal
                  assert: len(@@.green$) >= 2

                - desc: all colors must be less than 100
                  lang: internal
                  assert: all(@@.'^(red|green|blue)$' < 100)

                - desc: red must be the smallest in both one and two
                  lang: internal
                  assert: all([min($x.*) == $x.red for x in [one, two]])

        fowl:
            - chicken:
                - a:
                    red: 101
                    blue: 102

                  b:
                    red: -2
                    blue: -3

            - turkey:
                - x: 15
                  y: 30
                - x: 25
                  y: 50

        assertions:
            - desc: at least one red must be > 100
              lang: internal
              assert: exists(@@.red > 100)

            - desc: there must be exactly three negative color values
              lang: internal
              assert: count(@@.'^(red|green|blue)$' < 0) == 3

            - desc: turkey y's must always be twice the corresponding x's
              lang: internal
              assert: all([$t.y == 2 * $t.x for t in @@.turkey])
`

	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{Silent: true})
	require.NoError(t, err)

	yaml1 := strings.ReplaceAll(yaml, `red: 17`, `red: 77`)
	root1, err := yt.ReadYamlFromString(yaml1, "testfile")
	require.NoError(t, err)
	root2, err := pp.ProcessAssertions(root1, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)
	require.Regexp(t, regexp.MustCompile(`red must be the smallest`), err.Error())

	require.Empty(t, yt.MatchingPaths(root2, yt.NewPathPatternOk("@@.assertions")))
}

func TestStaticStandardLanguageAssertions(t *testing.T) {
	yaml := `
        services:
          http:
            tcp: 80
          https:
            tcp: 443
          ssh:
            tcp: 22
          mktprot:
            udp: 54321
          ping:
            icmp:
              type: request-response
              type_codes: 128,129

        communications:
          hierarchy:
            - divisions
            - regions
          divisions:
            divA:
              desc: division A
              assertions:
                # assertions for all components of division A (including all its regions)

                - desc: 1. admin users can access all offered services
                  assert: allowed if ds1.role = admin

                - desc: 2. admin users can access all offered services (verbose form)
                  assert: any allowed if ds1.role = admin

                - desc: 3. admin users can access all offered tcp services
                  assert: tcp allowed if ds1.role = admin

                - desc: 4. admin users can access all offered tcp services (verbose form)
                  assert: any tcp allowed if ds1.role = admin

                - desc: 5. admin users can access all offered tcp and udp services
                  assert: tcp and udp allowed if ds1.role = admin

                - desc: 6. admin users can access all offered tcp and udp services (verbose form)
                  assert: any tcp and udp allowed if ds1.role = admin

                #- desc: 7. admin users can ssh to every component
                #  assert: tcp 22 allowed if ds1.role = admin

                - desc: 8. admin users can ssh to every component that offers ssh
                  assert: any tcp 22 allowed if ds1.role = admin

                - desc: 9. any access offered by any component must be accessible by admin
                  assert: allowed if ds1.role = admin

                - desc: 10. any access offered by any component must be accessible by admin (verbose form)
                  assert: any allowed if ds1.role = admin

                - desc: 11. any tcp or udp access offered by any component must be accessible by admin
                  assert: tcp and udp allowed if ds1.role = admin

                - desc: 12. any tcp or udp access offered by any component must be accessible by admin (verbose form)
                  assert: any tcp and udp allowed if ds1.role = admin

                #- desc: 13. admin users get ssh and https access to every component (version 1)
                # assert: tcp 22 and tcp 443 allowed if ds1.role = admin

                #- desc: 14. admin users get ssh and https access to every component (version 2)
                #  assert: tcp 22,443 allowed if ds1.role = admin

                - desc: 15. admin users get ssh and https access to every component that offers both of them
                  assert: any tcp 22 and tcp 443 allowed if ds1.role = admin

                #- desc: 16. admin users get ssh access to every component and udp and icmp access to every component that offers them
                #  assert: tcp 22 and udp and icmp allowed if ds1.role == admin

                #- desc: 17. every component must allow https access at up to 10 Mbps for at least 1 hour to every employee
                #  assert: tcp 443 allowed with max(bandwidth) >= 10Mbps and max(duration) >= 1h if ds0.roles has employee

                - desc: 18. no nonadmin nonemployee can access any udp or icmp
                  domain: local
                  assert: udp and icmp not allowed if ds0.roles excludes employee and ds1.role ne admin

                - desc: 19. no nonadmin nonemployee can access any udp or icmp (verbose form)
                  domain: local
                  assert: any udp and icmp not allowed if ds0.roles excludes employee and ds1.role ne admin

                - desc: 20. no non-admin user can ssh to any component
                  domain: global
                  assert: tcp 22 not allowed if ds1.role != admin

                - desc: 21. no component may allow access to tcp ports 1 through 21 or 23 or to udp port 1234
                  assert: tcp 1-21,23 and udp 1234 not allowed

                - desc: 22. no component may allow https access at more than 20 Mbps to anyone
                  assert: tcp 443 not allowed with max(bandwidth) > 20Mbps

                - desc: 23. no component may allow specialudp access to anyone in marketing other than admins
                  assert: udp 54321 not allowed if ds0.department == marketing and ds1.role != admin

                - desc: 24. no visa for tcp access may have a lifetime of more than two hours
                  assert: tcp not allowed with max(duration) > 2h

                - desc: 25. no visa may have a lifetime of more than four hours
                  assert: not allowed with max(duration) > 4h

              components:
                comp0:
                  desc: division A component 0 (web)
                  services:
                    - https
                  provider:
                    - [ds0.access, eq, public]
                  policies:
                    - desc: all employees get https access
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, employee]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 2h
                    - desc: admin gets https access
                      conditions:
                         - desc: admin only
                           attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h
                comp0_1:
                  desc: division A component 0_1 (ssh)
                  services:
                    - ssh
                  provider:
                    - [ds0.access, eq, public]
                  policies:
                    - desc: admin gets ssh access
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h
                comp1:
                  desc: division A component 1 (https)
                  services:
                    - https
                  provider:
                    - [ds0.access, eq, public]
                  policies:
                    - desc: all employees get https access
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, employee]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h
                    - desc: admin gets access to everything
                      conditions:
                         - desc: admin only
                           attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps

                comp1_1:
                  desc: division A component 1_1 (ssh)
                  services:
                    - ssh
                  provider:
                    - [ds0.access, eq, public]
                  policies:
                    - desc: admin gets access to everything
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps

                comp1_2:
                  desc: division A component 1_2 (marketing)
                  services:
                    - mktprot
                  provider:
                    - [ds0.access, eq, public]
                  policies:
                    - desc: specialudp
                      conditions:
                          - desc: non-marketing employees only
                            attrs:
                              - [ds0.roles, has, employee]
                              - [ds0.department, ne, marketing]
                      constraints:
                        duration: 4h
                    - desc: admin gets access to everything
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps

              regions:
                regX:
                  desc: division A region X
                  assertions:
                    # Assertions for all components of division A, region X

                    # TODO: Not sure why this one does not work
                    #- desc: X1. non-marketing contractors can ping every component
                    #  assert: icmp 128,129 allowed if ds0.roles has contractor and ds1.department != marketing

                    - desc: X2. no one other than admins and (some) contractors can ping any component
                      assert: icmp not allowed if ds1.role != admin and ds0.roles excludes contractor

                    - desc: X3. no one other than admins and (some) non-marketing users can ping any component
                      assert: icmp not allowed if ds1.role != admin and ds1.department == marketing

                    - desc: X4. no non-admin marketing user has any icmp access
                      assert: icmp not allowed if ds0.roles eq marketing and ds1.role ne admin

                  components:
                    comp0:
                      desc: division A region X component 0 (https)
                      services:
                        - https
                      policies:
                        - desc: all employees get https access
                          conditions:
                            - desc: general employee access
                              attrs:
                                - [ds0.roles, has, employee]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h
                        - desc: admins get https
                          conditions:
                             - desc: admin only
                               attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h

                    comp0_1:
                      desc: division A region X component 0_1 (22)
                      services:
                        - ssh
                      policies:
                        - desc: admins get ssh
                          conditions:
                              - desc: admin only
                                attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h

                    comp0_2:
                      desc: division A region X component 0_2 (ping)
                      services:
                        - ping
                      policies:
                        - desc: admins get icmp
                          conditions:
                              - desc: admin only
                                attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h
                        - desc: non-marketing contractors get ping access
                          conditions:
                              - desc: non-marketing contractors
                                attrs:
                                  - [ds0.roles, has, contractor]
                                  - [ds1.department, ne, marketing]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h

                    comp1:
                      desc: division A region X component 1 (443)
                      services:
                        - https
                      policies:
                        - desc: all employees get https access
                          conditions:
                            - desc: general employee access
                              attrs:
                                - [ds0.roles, has, employee]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h
                        - desc: admins get https access
                          conditions:
                             - desc: admin only
                               attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h

                    comp1_1:
                      desc: division A region X component 1_1 (22)
                      services:
                        - ssh
                      policies:
                        - desc: admins get ssh
                          conditions:
                              - desc: admin only
                                attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h

                    comp1_2:
                      desc: division A region X component 1_2 (ping)
                      services:
                        - ping
                      policies:
                        - desc: admins get icmp
                          conditions:
                              - desc: admin only
                                attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h
                        - desc: non-marketing contractors get ping access
                          conditions:
                              - desc: non-marketing contractors
                                attrs:
                                  - [ds0.roles, has, contractor]
                                  - [ds1.department, ne, marketing]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h


        assertions:
          # Local-domain assertions find "nearest" components block, so must work from this level too.

          - desc: L1. no nonadmin nonemployee can access any udp or icmp (top-level)
            domain: local
            assert: udp and icmp not allowed if ds0.roles excludes employee and ds1.role ne admin
`
	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{Silent: false, TraceAsserts: "@@", DynamicAsserts: true})
	// _, err = pp.ProcessAssertions(root, nil, os.Stderr, &pp.PreprocessOpts{TraceAsserts: "@@.assertions[*].desc$'every component.*up to 10 Mbps.*at least 1 h'"})
	require.NoError(t, err)

	yaml0 := strings.Replace(yaml, `[ds1.role, eq, admin]`, `[ds1.role, eq, notadmin]`, 1)
	root0, err := yt.ReadYamlFromString(yaml0, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root0, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)

	yaml1 := strings.Replace(yaml, `tcp 1-21,23 and udp 1234 not allowed`, `tcp 1-22,23 and udp 1234 not allowed`, 1)
	root1, err := yt.ReadYamlFromString(yaml1, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root1, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)

	yaml2 := strings.Replace(yaml, `tcp 443 not allowed with max(bandwidth) > 20Mbps`, `tcp 443 not allowed with max(bandwidth) > 19Mbps`, 1)
	root2, err := yt.ReadYamlFromString(yaml2, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root2, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)

	yaml3 := regexp.MustCompile(`(no nonadmin nonemployee can access any udp or icmp\s*domain:) local`).ReplaceAllString(yaml, `$1 global`)
	root3, err := yt.ReadYamlFromString(yaml3, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root3, nil, nil, &pp.PreprocessOpts{})
	require.Error(t, err)

	// TODO: This no longer works with mathias changes.
	//yaml4 := regexp.MustCompile(`(no nonadmin nonemployee can access any udp or icmp \(top-level\)\s*domain:) local`).ReplaceAllString(yaml, `$1 global`)
	//root4, err := yt.ReadYamlFromString(yaml4, "testfile")
	//require.NoError(t, err)
	//_, err = pp.ProcessAssertions(root4, nil, nil, &pp.PreprocessOpts{})
	//require.Error(t, err)
}

func TestDynamicStandardLanguageAssertions(t *testing.T) {
	yaml := `
        services:
          ping:
            icmp:
              type: request-response
              type_codes: 128,129
          http:
            tcp: 80
          https:
            tcp: 443
          ssh:
            tcp: 22
          customudp:
            udp: 54321

        communications:
          hierarchy:
            - divisions
            - regions
          divisions:
            divA:
              desc: division A
              assertions:
                - desc: 1. every type of access must have at least one authorized actor
                  assert: allowed for count(users) > 0

                - desc: 2. all offered tcp and udp access must have at least one authorized actor
                  assert: tcp and udp allowed for count(users) > 0

                - desc: 3. fewer than 6 users have access to any service of any component
                  assert: allowed for count(users) < 6

                - desc: 4. there are exactly 5 users authorized for visas for udp 54321
                  assert: any udp 54321 allowed for count(users) == 5

                - desc: 5. up to five admin users can ssh to every component
                  assert: tcp 22 allowed for count(users) <= 5 if ds1.role = admin

                - desc: 6. fewer than five admin users can ssh to every component that offers ssh
                  assert: any tcp 22 allowed for count(users) < 5 if ds1.role = admin

                #- desc: 7. at least two and not more than 5 admin users can ssh to every component
                #  assert: tcp 22 allowed for count(users) >= 2 and count(users) <= 5 if ds1.role = admin

                - desc: 8. at least two admin users can ssh to every component that offers ssh
                  assert: any tcp 22 allowed for count(users) >= 2 if ds1.role = admin

                #- desc: 9. exactly four admin users can ssh to every component
                #  assert: tcp 22 allowed for count(users) == 4 if ds1.role = admin

                - desc: 10. fewer than 100 admin users can access tcp 17 and udp 42 of every component
                  assert: tcp 17 and udp 42 allowed for count(users) < 100 if ds1.role = admin

                - desc: 11. more than 0 admin users can access tcp 22 and udp 54321 of every component that offers them
                  assert: any tcp 22 and udp 54321 allowed for count(users) > 0 if ds1.role = admin

                - desc: 12. between 1 and 4 admin users can access tcp 22 and udp 54321 of every component that offers them
                  assert: any tcp 22 and udp 54321 allowed for count(users) > 0 and count(users) < 5 if ds1.role = admin

                - desc: 13. no users are authorized for any visas with lifetimes of over 4 hours
                  assert: any allowed with max(duration) > 4h for count(users) == 0

                - desc: 14. there are exactly 3 users authorized for visas (for any service) with lifetimes of over 3 hours
                  assert: any allowed with max(duration) > 3h for count(users) == 3

                - desc: 15. there is one contractor in finance authorized to ping some component
                  assert: any icmp 128,129 allowed for count(users) == 1 if ds0.roles has contractor and ds0.department == finance

                - desc: 16. at most 4 users can access any tcp at over 15 Mbps
                  assert: tcp allowed with max(bandwidth) > 15Mbps for count(users) <= 4

                - desc: 17. at most 5 users can access any tcp at over 5 Mbps
                  assert: tcp allowed with max(bandwidth) > 5Mbps for count(users) <= 5

              components:
                comp0:
                  desc: division A component 0
                  services:
                    - https
                  policies:
                    - desc: all employees get https access
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, employee]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 2h
                    - desc: admin gets https
                      conditions:
                         - desc: admin only
                           attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h
                comp0_1:
                  desc: division A component 0_1
                  services:
                    - ssh
                  policies:
                    - desc: admin gets ssh access
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        bandwidth: 20Mbps
                        duration: 1h

                comp1:
                  desc: division A component 1
                  services:
                    - https
                  policies:
                    - desc: all employees get https access
                      conditions:
                        - desc: general employee access
                          attrs:
                            - [ds0.roles, has, employee]
                      constraints:
                        bandwidth: 10Mbps
                        duration: 1h
                    - desc: admin gets access to everything
                      conditions:
                         - desc: admin only
                           attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps
                comp1_1:
                  desc: division A component 1_1
                  services:
                    - customudp
                  policies:
                    - desc: specialudp
                      conditions:
                          - desc: non-marketing employees only
                            attrs:
                              - [ds0.roles, has, employee]
                              - [ds0.department, ne, marketing]
                      constraints:
                        duration: 4h
                    - desc: admin gets access to everything
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps
                comp1_2:
                  desc: division A component 1_2
                  services:
                    - ssh
                  policies:
                    - desc: admin gets access to everything
                      conditions:
                          - desc: admin only
                            attrs:
                              - [ds1.role, eq, admin]
                      constraints:
                        duration: 1h
                        bandwidth: 20Mbps

              regions:
                regX:
                  desc: division A region X
                  components:
                    compX_0:
                      services:
                        - https
                      desc: division A region X component 0
                      policies:
                        - desc: all employees get https access
                          conditions:
                            - desc: general employee access
                              attrs:
                                - [ds0.roles, has, employee]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h
                        - desc: admins get icmp, ssh, and https access
                          conditions:
                             - desc: admin only
                               attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 20Mbps
                            duration: 2h
                    compX_1:
                      desc: division A region X component 0_1
                      services:
                        - ping
                      policies:
                        - desc: admins get icmp, ssh, and https access
                          conditions:
                              - desc: admin only
                                attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 20Mbps
                            duration: 2h
                        - desc: non-marketing contractors get ping access
                          conditions:
                              - desc: non-marketing contractors
                                attrs:
                                  - [ds0.roles, has, contractor]
                                  - [ds0.department, ne, marketing]
                          constraints:
                            bandwidth: 10Mbps
                            duration: 2h
                    compX_2:
                      desc: division A region X component 0_2
                      services:
                        - ssh
                      policies:
                        - desc: admins get icmp, ssh, and https access
                          conditions:
                              - desc: admin only
                                attrs:
                                  - [ds1.role, eq, admin]
                          constraints:
                            bandwidth: 20Mbps
                            duration: 2h

      `

	dsProxies := map[string]pp.DataSourceProxy{
		"ds0": &testDataSourceProxy{map[string]map[string]string{
			"id0001": map[string]string{"name": "John Doe", "department": "engineering", "roles": "employee,admin"},
			"id0002": map[string]string{"name": "Joe Blow", "department": "engineering", "roles": "employee,admin"},
			"id0003": map[string]string{"name": "Joe Schmoe", "department": "marketing", "roles": "employee,admin"},
			"id0004": map[string]string{"name": "Moe Howard", "department": "medicine", "roles": "employee,doctor"},
			"id0005": map[string]string{"name": "P. T. Barnum", "department": "marketing", "roles": "contractor"},
			"id0006": map[string]string{"name": "J. P. Morgan", "department": "finance", "roles": "contractor"}}},
		"ds1": &testDataSourceProxy{map[string]map[string]string{
			"id0001": map[string]string{"name": "John Doe", "role": "admin", "something": "else"},
			"id0002": map[string]string{"name": "Joe Blow", "role": "admin", "something": "else"},
			"id0003": map[string]string{"name": "Joe Schmoe", "role": "admin", "something": "else"},
			"id0007": map[string]string{"name": "Jane Doe", "role": "admin", "something": "else"}}},
	}

	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root, dsProxies, os.Stderr, &pp.PreprocessOpts{Silent: true, DynamicAsserts: true})
	require.NoError(t, err)

	yaml1 := strings.ReplaceAll(yaml, `assert: allowed for count(users) < 6`, `assert: allowed for count(users) < 5`)
	root1, err := yt.ReadYamlFromString(yaml1, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root1, dsProxies, nil, &pp.PreprocessOpts{Silent: true, DynamicAsserts: true})
	// _, err = pp.ProcessAssertions(root1, dsProxies, os.Stderr, &pp.PreprocessOpts{DynamicAsserts: true, TraceAsserts: `@@.assertions[*].assert$"allowed for count(users) < 5"`})
	require.Error(t, err)

	yaml2 := strings.ReplaceAll(yaml, `ds0.department == finance`, `ds0.department == purchasing`)
	root2, err := yt.ReadYamlFromString(yaml2, "testfile")
	require.NoError(t, err)
	_, err = pp.ProcessAssertions(root2, dsProxies, nil, &pp.PreprocessOpts{Silent: true, DynamicAsserts: true})
	require.Error(t, err)
}

func TestStandardLanguageAssertionSyntaxErrors(t *testing.T) {
	exprs := []string{
		"wut",
		"allowed with",
		"allowed with foo < 10",
		"allowed with max(bandwidth) < 10",
		"allowed with max(bandwidth) lessthan 10Mbps",
		"allowed with max(bandwidth) < 10Mxps",
		"allowed with max(bandwidth) < 10 Mbps",
		"allowed with max(bandwidth) < 10Mbps and",
		"allowed with and max(bandwidth) < 10Mbps",
		"allowed with min(bandwidth) < 10Mbps",
		"allowed with max(duration) <",
		"allowed with max(duration) < 10",
		"allowed with max(duration) < 10X",
		"allowed with max(duration) < 10 h",
		"allowed with max(headroom) > 1",
		"allowed if",
		"allowed if foo is bar",
		"allowed if and foo == bar",
		"allowed if foo == bar and",
		"not allowed with",
		"not allowed with foo > 10",
		"not allowed with max(bandwidth) > 10",
		"not allowed with max(bandwidth) lessthan 10Mbps",
		"not allowed with max(bandwidth) > 10Mxps",
		"not allowed with max(bandwidth) > 10 Mbps",
		"not allowed with max(bandwidth) > 10Mbps and",
		"not allowed with and max(bandwidth) > 10Mbps",
		"not allowed with max(duration) >",
		"not allowed with max(duration) > 10",
		"not allowed with max(duration) > 10X",
		"not allowed with max(duration) > 10 h",
		"not allowed with max(headroom) > 1",
		"not allowed if",
		"not allowed if foo is bar",
		"not allowed if and foo == bar",
		"not allowed if foo == bar and",
		"allowed for count(what) > 0",
		"allowed for count(users) >",
		"allowed for count(users) < 5 if foo",
		"allowed for count(users) > 0 and",
		"not allowed for count(users) > 0",
		"tcp x allowed if foo == bar",
		"udp 1- allowed if foo == bar",
		"udp 1-x allowed if foo == bar",
		"icmp 1,x allowed if foo == bar",
		"foo allowed if foo == bar",
	}

	for _, expr := range exprs {
		yaml := "assertions: [{desc: test, assert: " + expr + "}]"
		root, err := yt.ReadYamlFromString(yaml, "")
		require.NoError(t, err, expr)
		_, err = pp.ProcessAssertions(root, nil, nil, &pp.PreprocessOpts{})
		require.Error(t, err, expr)
	}
}
