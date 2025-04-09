package policy_test

/* XXX BROKEN FOR NOW

type TestState struct {
	SelfFlag      bool
	Sets          []pb.FlagT
	RegisterCalls int // number of calls
	RegName       string
	RegType       pb.SvcT
	RegEndpoints  []string
	ConstSid      uint32
	ExpSid        uint32
	AuthDomain    string
	AuthSpec      string
	ConnectVia    string
	Cfg           map[string]string
}

type TestSess struct {
	pep            string
	ConstrainCalls int
	ExpAfter       time.Duration
	ConstVal       uint64
	ExpCalls       int
}

// begin vm.State interface
func (ts *TestState) IsSelf() bool {
	return ts.SelfFlag
}

func (ts *TestState) SatisfiesAuth(authName string) bool {
	return authName == ts.AuthDomain
}

func (ts *TestState) DoesConnectVia(cv string) bool {
	return cv == ts.ConnectVia
}

func (ts *TestState) SetConfig(key, value string) error {
	if ts.Cfg == nil {
		ts.Cfg = make(map[string]string)
	}
	ts.Cfg[key] = value
	return nil
}

func (ts *TestState) RegisterService(name string, stype pb.SvcT, endpoints []string) error {
	ts.RegisterCalls++
	ts.RegName = name
	ts.RegType = stype
	ts.RegEndpoints = endpoints
	return nil
}

func (ts *TestState) SetFlag(ft pb.FlagT) error {
	ts.Sets = append(ts.Sets, ft)
	return nil
}

func (tss *TestSess) ConstrainBandwidth(bwVal uint64) {
	tss.ConstrainCalls++
	tss.ConstVal = bwVal
}

func (tss *TestSess) ExpireSessionAfter(after time.Duration) error {
	tss.ExpCalls++
	tss.ExpAfter = after
	return nil
}

func (ts *TestState) RequireSignedCert(certType, authID uint32, props map[string]string) {}

func (tss *TestSess) SetPEP(n string) error {
	tss.pep = n
	return nil
}

// end vm.State interface

func pdlToDB(t *testing.T, pdltxt string) *rbac.StaticDB {
	pp := pdl.NewPreprocessor(pdl.DefaultIncludes)
	pprdr, err := pp.Process(strings.NewReader(pdltxt))
	require.Nil(t, err)

	buf, _ := ioutil.ReadAll(pprdr)
	fmt.Printf("POLICY:\n%v\n\n", string(buf))

	// itms, err := pdl.Parse(pprdr)
	rawItms, err := pdl.Parse(strings.NewReader(string(buf)))
	require.Nil(t, err)

	itms, err := pdlc.CoalesceItems(rawItms)
	require.Nil(t, err)

	db, err := rbac.NewStaticDBWithItems(itms)
	require.Nil(t, err)
	return db
}

func TestApplyICMPEchoReply(t *testing.T) {
	// Create a policy that allows one host to ping another:
	ptxt := `#include <ping>
	role auth0 -p auth0.spacelaser.net -t auth -b tcp/5001
	role auth0client -c service/auth0.spacelaser.net,max_bw=1Mbps
	actor aa -a sn.epid=85V3ws1T7TqekzRSh51rUmBTK2dh -a sn.authority=auth0.spacelaser.net
	actor bb -a sn.epid=85V3wrhhpaeNVg2ZQv9MAjwoau7R -a sn.authority=auth0.spacelaser.net
	#
	grant aa -r auth0 -r surenet.Pingable
	grant bb -r auth0client -r surenet.Pinger`
	db := pdlToDB(t, ptxt)
	pol := &pb.Policy{}
	comp := pdlc.NewCompiler()
	cdb, err := pdlc.NewClaimsDB(db)
	require.Nil(t, err)
	err = comp.GenerateMatchers(db, cdb, pol)
	require.Nil(t, err)

	// Now we have a policy, lets see if apply works properly for an ICMP echo reply.

	// Pick out our pline for ICMP echo request (for the session ID)
	var matchLine []byte
	for _, ln := range pol.GetPlines() {
		if bin.GetProtocol(ln) == snip.ProtocolICMP {
			if _, dp := bin.GetPorts(ln); dp == 128 { // 128 = echo_request
				matchLine = ln
				break
			}
		}
	}
	require.NotNil(t, matchLine)

	procIdx := bin.GetProcID(matchLine)
	proc := pol.GetProcs()[procIdx]
	require.NotNil(t, proc)
	{
		env := &vm.PEnv{
			PLine: matchLine,
			Env: map[string]string{
				vm.PEK_SrcZprAddr: "fc00:3001:26f4:851a:7f0:e98d:1373:32d",
				vm.PEK_DstZprAddr: "fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59",
			},
			Forward: true,
		}
		conf, err := vm.ExecVProc(proc, env)
		require.Nil(t, err)
		require.Equal(t, uint32(vm.PEPDockICMP), conf.DockPEP)

		// Should allow a ping from src -> dst with no antecedent required.
		pepArgs := &snio.PEPArgsICMP{}
		err = proto.Unmarshal(conf.DockPEPArgs, pepArgs)
		require.Nil(t, err)
		require.Equal(t, uint32(0xFF), pepArgs.GetIcmpAntecedent())
		require.Equal(t, uint32(128), pepArgs.GetIcmpTypeCode())
	}

	// Now see what happens if we go the other way.
	matchLine = nil
	for _, ln := range pol.GetPlines() {
		if bin.GetProtocol(ln) == snip.ProtocolICMP {
			if _, dp := bin.GetPorts(ln); dp == 129 {
				matchLine = ln
				break
			}
		}
	}
	require.NotNil(t, matchLine)

	procIdx = bin.GetProcID(matchLine)
	proc = pol.GetProcs()[procIdx]
	require.NotNil(t, proc)
	{
		env := &vm.PEnv{
			PLine: matchLine,
			Env: map[string]string{
				vm.PEK_DstZprAddr: "fc00:3001:26f4:851a:7f0:e98d:1373:32d",
				vm.PEK_SrcZprAddr: "fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59",
			},
			Forward: true,
		}
		conf, err := vm.ExecVProc(proc, env)
		require.Nil(t, err)
		require.Equal(t, uint32(vm.PEPDockICMP), conf.DockPEP)

		// Should allow a reply from dst -> src with no antecedent required.
		pepArgs := &snio.PEPArgsICMP{}
		err = proto.Unmarshal(conf.DockPEPArgs, pepArgs)
		require.Nil(t, err)
		require.Equal(t, uint32(128), pepArgs.GetIcmpAntecedent())
		require.Equal(t, uint32(129), pepArgs.GetIcmpTypeCode())
	}

}

func TestApplySetConfig(t *testing.T) {
	ptxt := `#include <node>
	role auth0 -p auth0.spacelaser.net -t auth -b tcp/5001
	role auth0client -c service/auth0.spacelaser.net,max_bw=1Mbps
	role n0 -p n0.spacelaser.net
	actor aa -a sn.epid=85V3ws1T7TqekzRSh51rUmBTK2dh -a sn.authority=auth0.spacelaser.net
	actor bb -a sn.epid=85V3wrhhpaeNVg2ZQv9MAjwoau7R -a sn.authority=auth0.spacelaser.net
	#
	grant aa -r auth0
	grant bb -r n0 -r auth0client -r surenet.Node`
	db := pdlToDB(t, ptxt)

	pol := &pb.Policy{}
	comp := pdlc.NewCompiler()
	// The setconfig stuff happens in connects
	cdb, err := pdlc.NewClaimsDB(db)
	require.Nil(t, err)
	err = comp.GenerateConnects(db, cdb, pol)
	require.Nil(t, err)

	nodeEp, _ := snip.HumanStringToEPID("85V3wrhhpaeNVg2ZQv9MAjwoau7R")

	// Pick out our pline for ICMP echo reply
	var matchLine []byte
	for _, ln := range pol.GetPlines() {
		if bin.IsConnectionLine(ln) && nodeEp.IP().Equal(bin.GetSrc(ln)) {
			matchLine = ln
			break
		}
	}
	require.NotNil(t, matchLine)

	procIdx := bin.GetProcID(matchLine)
	proc := pol.GetProcs()[procIdx]
	require.NotNil(t, proc)

	fmt.Printf("%v\n", proc.Pseudocode())

	ts := &TestState{
		AuthDomain: "auth0.spacelaser.net",
		AuthSpec:   "ca-v1-sha256",
		SelfFlag:   true,
	}

	pass, fc := vm.Apply(proc, ts, 0)
	require.Equal(t, vm.FailNone, fc)
	assert.True(t, pass)

	err = vm.ExecCProc(proc, ts)
	require.Nil(t, err)
	require.Contains(t, ts.Sets, pb.FlagT_F_NODE)             // sets node flag
	require.Equal(t, "service/n0.spacelaser.net", ts.RegName) // register node service
	require.Equal(t, "fc00:3001:0:1::/64", ts.Cfg[pb.ConfKeyCIDR])
}



*/
