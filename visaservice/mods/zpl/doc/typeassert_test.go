package doc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/doc"
)

func testPasses(t *testing.T, f func(string) error, allows []string) {
	for _, v := range allows {
		require.Nil(t, f(v), "failed to allow: %v", v)
	}
}

func testFails(t *testing.T, f func(string) error, denies []string) {
	for _, v := range denies {
		require.NotNil(t, f(v), "failed to deny: %v", v)
	}
}

func TestValidID(t *testing.T) {
	testPasses(t, doc.AssertValidID, []string{
		"123",
		"foo",
		"fee",
		"this.is.ok_idXX123",
	})
	testFails(t, doc.AssertValidID, []string{
		"foo/fie",
		"how-about-some-hyphens",
		"?thisisnobueno?",
		"spaces too",
		"no:no:no",
	})
}

func TestValidRevision(t *testing.T) {
	testPasses(t, doc.AssertValidRevision, []string{
		"0fa2c59d589b5f4f580fa3f9b473958e15772dd2",
		"rev123",
		"v0.2.1",
	})
	testFails(t, doc.AssertValidRevision, []string{
		"ha ha ha",
		"-_/?&&&",
		"",
	})
}

func TestValidHierarchy(t *testing.T) {
	testPasses(t, doc.AssertValidHierarchy, []string{
		"hello",
		"hello1",
		"hello_is_it_me_youre_looking_for",
	})
	testFails(t, doc.AssertValidHierarchy, []string{
		"hel lo",
		"foo/bar",
		"what time is it?",
		"what.time.is.it",
	})
}

func TestValidDefine(t *testing.T) {
	testPasses(t, doc.AssertValidDefine, []string{
		"apolicy",
		"foo_bah",
		"this:that:theother:1",
		"this-too",
		"1-thing.more",
		"PRETTY.great:::12345",
	})
	testFails(t, doc.AssertValidDefine, []string{
		"no spaces",
		"(*^@#$(*&",
		"no/slash/for/you",
	})
}

func TestValidAuthPrefix(t *testing.T) {
	testPasses(t, doc.AssertValidAuthPrefix, []string{
		"ca0",
		"simplev",
		"auth.intern",
		"auth:intern-1",
		"a.intern_1:x5-alpha",
	})
	testFails(t, doc.AssertValidAuthPrefix, []string{
		"no spaces",
		"(*^@#$(*&",
		"no/slash/for/you",
		".leading-dot",
		"-leading-dash",
		":leading-colon",
	})
}

func TestValidNetAddr(t *testing.T) {
	testPasses(t, doc.AssertValidNetAddr, []string{
		"foo:1",
		"some.host.name:31337",
		"127.0.0.1:5000",
		"[fc00:3001::1]:80",
	})
	testFails(t, doc.AssertValidNetAddr, []string{
		"foo:12345678",
		"foo",
		"foo:",
		"foo:-1000",
		"99",
	})
}

func TestValidPortType(t *testing.T) {
	testPasses(t, doc.AssertValidPortType, []string{
		"123",
		"1",
		"1,2,3",
		"1,  2,     3",
		"10-20",
		"1-1",
		"1-10, 11, 12, 20, 100-200, 65534",
	})
	testFails(t, doc.AssertValidPortType, []string{
		"5-1",
		"-1",
		"0",
		"ha ho",
		"1, 2, 3, a, b, c",
		"1--10",
		"1,,,,4",
		"1,",
		",1",
	})
}

func TestValidZPRAddress(t *testing.T) {
	testPasses(t, doc.AssertValidZPRAddress, []string{
		"doc.cat.zebra",
		"foo.com",
		"fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59",
		"127.0.0.1", // allows this but maybe should not?
	})
	testFails(t, doc.AssertValidZPRAddress, []string{
		"dog cat zebra",
	})
}

func TestValidAttrExpr(t *testing.T) {
	makeAttrExpr := func(key string, op string, val string) *doc.AttrExpr {
		k, _ := doc.NewZplString(key)
		o, _ := doc.NewZplString(op)
		v, _ := doc.NewZplString(val)
		return &doc.AttrExpr{nil, k, o, v}
	}
	require.Nil(t, doc.AssertValidAttrExpr(makeAttrExpr("foo", "eq", "fee")))
	require.Nil(t, doc.AssertValidAttrExpr(makeAttrExpr("k2", "ne", "2")))
	require.Nil(t, doc.AssertValidAttrExpr(makeAttrExpr("k7", "has", "2")))
	require.Nil(t, doc.AssertValidAttrExpr(makeAttrExpr("k8", "excludes", "2")))
	require.Nil(t, doc.AssertValidAttrExpr(makeAttrExpr("this.and", "eq", "that too")))
	require.Nil(t, doc.AssertValidAttrExpr(makeAttrExpr("space in key", "eq", "is ok?")))
	require.NotNil(t, doc.AssertValidAttrExpr(nil))
	require.NotNil(t, doc.AssertValidAttrExpr(makeAttrExpr("k", "o", "")))
	require.NotNil(t, doc.AssertValidAttrExpr(makeAttrExpr("k", "", "v")))
	require.NotNil(t, doc.AssertValidAttrExpr(makeAttrExpr("", "o", "v")))
	require.NotNil(t, doc.AssertValidAttrExpr(makeAttrExpr("k", "", "v")))
	require.NotNil(t, doc.AssertValidAttrExpr(makeAttrExpr("k", "badop", "v")))
}

func TestValidIPv6CIDR(t *testing.T) {
	testPasses(t, doc.AssertValidIPv6CIDR, []string{
		"fc00::/32",
		"fc00:3001::/8",
	})
	testFails(t, doc.AssertValidIPv6CIDR, []string{
		"10.1.1.0/32",
		"foo bah",
	})
}

func TestPositiveInteger(t *testing.T) {
	require.Nil(t, doc.AssertPositiveInteger(33, ""))
	require.Nil(t, doc.AssertPositiveInteger(1, ""))
	require.NotNil(t, doc.AssertPositiveInteger(0, ""))
	require.NotNil(t, doc.AssertPositiveInteger(-1, ""))
}

func TestValidDSAPISpec(t *testing.T) {
	require.Nil(t, doc.AssertValidDSAPISpec("query/3"))
	require.Nil(t, doc.AssertValidDSAPISpec("validation/1"))
	require.Nil(t, doc.AssertValidDSAPISpec("query/3;validation/1"))
	require.Nil(t, doc.AssertValidDSAPISpec("query/3; validation/1"))
	require.NotNil(t, doc.AssertValidDSAPISpec("nope"))
	require.NotNil(t, doc.AssertValidDSAPISpec("query 99"))
	require.NotNil(t, doc.AssertValidDSAPISpec("admin/88"))
	require.NotNil(t, doc.AssertValidDSAPISpec("query/3; validation/1;"))
	require.NotNil(t, doc.AssertValidDSAPISpec("query/3; validation/1; pipsqueak/4"))
	require.NotNil(t, doc.AssertValidDSAPISpec("query/3; validation/1; query/4"))
}

func TestValidNoisePK(t *testing.T) {
	require.NotNil(t, doc.AssertValidNoisePK("foo"))
	require.NotNil(t, doc.AssertValidNoisePK("abff01"))
	require.NotNil(t, doc.AssertValidNoisePK("000102030405060708091011121314151617181920212223242526272829303132"))

	require.Nil(t, doc.AssertValidNoisePK("0001020304050607080910111213141516171819202122232425262728293031"))
	require.Nil(t, doc.AssertValidNoisePK("13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"))
}
