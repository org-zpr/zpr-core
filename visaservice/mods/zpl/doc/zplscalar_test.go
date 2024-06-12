package doc_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/doc"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

func TestZplScalarTypesFromPaths(t *testing.T) {
	yaml := `---
        scalars:
            bool_true: true
            string_true: "true"
            int_1: 1
            float_2: 2.0
            string_3: "3"
            null:
            int_neg: -1
            uint_big: 9223372036854775809 # 2^63 + 1 (too big for int, no exact float64 rep)
            float_big: 184467440737095516169 # larger than 2^64 (too big for uint)
        nonscalars:
            sequence:
                - 0
            mapping:
                x: 0`

	root, err := yt.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)

	bt_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.bool_true`))[0]
	bt_zbool, err := doc.NewZplBoolean(bt_path)
	require.NoError(t, err)
	require.Exactly(t, true, bt_zbool.Value())
	require.Exactly(t, "scalars.bool_true", bt_zbool.Path())
	require.Exactly(t, []string{"testfile:3:24"}, bt_zbool.Sources())
	bt_zsc, err := doc.NewZplScalar(bt_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplBooleanType, bt_zsc.Type())
	require.Exactly(t, bt_zbool, bt_zsc.(doc.ZplBoolean))

	i1_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.int_1`))[0]
	i1_zint, err := doc.NewZplInteger(i1_path)
	require.NoError(t, err)
	require.Exactly(t, int64(1), i1_zint.Value())
	require.Exactly(t, "scalars.int_1", i1_zint.Path())
	require.Exactly(t, []string{"testfile:5:20"}, i1_zint.Sources())
	i1_zsc, err := doc.NewZplScalar(i1_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplIntegerType, i1_zsc.Type())
	require.Exactly(t, i1_zint, i1_zsc.(doc.ZplInteger))
	i1_zint_i, err := i1_zint.AsInt64()
	require.NoError(t, err)
	require.Exactly(t, int64(1), i1_zint_i)
	i1_zint_u, err := i1_zint.AsUint64()
	require.NoError(t, err)
	require.Exactly(t, uint64(1), i1_zint_u)
	i1_zint_f, err := i1_zint.AsFloat64()
	require.NoError(t, err)
	require.Exactly(t, float64(1), i1_zint_f)

	i1_zuns, err := doc.NewZplUnsigned(i1_path)
	require.NoError(t, err)
	require.Exactly(t, uint64(1), i1_zuns.Value())
	require.Exactly(t, "scalars.int_1", i1_zuns.Path())
	require.Exactly(t, []string{"testfile:5:20"}, i1_zuns.Sources())
	i1_zuns_i, err := i1_zuns.AsInt64()
	require.NoError(t, err)
	require.Exactly(t, int64(1), i1_zuns_i)
	i1_zuns_u, err := i1_zuns.AsUint64()
	require.NoError(t, err)
	require.Exactly(t, uint64(1), i1_zuns_u)
	i1_zuns_f, err := i1_zuns.AsFloat64()
	require.NoError(t, err)
	require.Exactly(t, float64(1), i1_zuns_f)

	f2_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.float_2`))[0]
	f2_zflt, err := doc.NewZplFloat(f2_path)
	require.NoError(t, err)
	require.Exactly(t, float64(2.0), f2_zflt.Value())
	require.Exactly(t, "scalars.float_2", f2_zflt.Path())
	require.Exactly(t, []string{"testfile:6:22"}, f2_zflt.Sources())
	f2_zsc, err := doc.NewZplScalar(f2_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplFloatType, f2_zsc.Type())
	require.Exactly(t, f2_zflt, f2_zsc.(doc.ZplFloat))
	f2_flt_i, err := f2_zflt.AsInt64()
	require.NoError(t, err)
	require.Exactly(t, int64(2), f2_flt_i)
	f2_flt_u, err := f2_zflt.AsUint64()
	require.NoError(t, err)
	require.Exactly(t, uint64(2), f2_flt_u)
	f2_flt_f, err := f2_zflt.AsFloat64()
	require.NoError(t, err)
	require.Exactly(t, float64(2), f2_flt_f)

	st_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.string_true`))[0]
	st_zstr, err := doc.NewZplString(st_path)
	require.NoError(t, err)
	require.Exactly(t, "true", st_zstr.Value())
	require.Exactly(t, "scalars.string_true", st_zstr.Path())
	require.Exactly(t, []string{"testfile:4:26"}, st_zstr.Sources())
	st_zsc, err := doc.NewZplScalar(st_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplStringType, st_zsc.Type())
	require.Exactly(t, st_zstr, st_zsc.(doc.ZplString))

	s3_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.string_3`))[0]
	s3_zstr, err := doc.NewZplString(s3_path)
	require.NoError(t, err)
	require.Exactly(t, "3", s3_zstr.Value())
	require.Exactly(t, "scalars.string_3", s3_zstr.Path())
	require.Exactly(t, []string{"testfile:7:23"}, s3_zstr.Sources())
	s3_zsc, err := doc.NewZplScalar(s3_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplStringType, s3_zsc.Type())
	require.Exactly(t, s3_zstr, s3_zsc.(doc.ZplString))

	n_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.null`))[0]
	n_zstr, err := doc.NewZplString(n_path)
	require.NoError(t, err)
	require.Exactly(t, "", n_zstr.Value())
	require.Exactly(t, "scalars.null", n_zstr.Path())
	require.Exactly(t, []string{"testfile:8:18"}, n_zstr.Sources())
	n_zsc, err := doc.NewZplScalar(n_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplStringType, n_zsc.Type())
	require.Exactly(t, n_zstr, n_zsc.(doc.ZplString))

	in_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.int_neg`))[0]
	in_zint, err := doc.NewZplInteger(in_path)
	require.NoError(t, err)
	_, err = doc.NewZplUnsigned(in_path)
	require.Error(t, err)
	_, err = in_zint.AsUint64()
	require.Error(t, err)

	ub_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.uint_big`))[0]
	ub_zuns, err := doc.NewZplUnsigned(ub_path)
	require.NoError(t, err)
	ub_zsc, err := doc.NewZplScalar(ub_path)
	require.NoError(t, err)
	require.Exactly(t, doc.ZplUnsignedType, ub_zsc.Type())
	require.Exactly(t, ub_zuns, ub_zsc.(doc.ZplUnsigned))
	_, err = doc.NewZplInteger(ub_path)
	require.Error(t, err)
	_, err = doc.NewZplFloat(ub_path)
	require.NoError(t, err)
	_, err = ub_zuns.AsInt64()
	require.Error(t, err)

	fb_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.float_big`))[0]
	fb_zflt, err := doc.NewZplFloat(fb_path)
	require.NoError(t, err)

	_, err = doc.NewZplInteger(fb_path)
	require.Error(t, err)

	_, err = doc.NewZplUnsigned(fb_path)
	require.Error(t, err)

	_, err = fb_zflt.AsInt64()
	require.Error(t, err)

	_, err = fb_zflt.AsUint64()
	require.Error(t, err)

	_, err = doc.NewZplBoolean(s3_path)
	require.Error(t, err)

	_, err = doc.NewZplInteger(bt_path)
	require.Error(t, err)

	_, err = doc.NewZplBoolean(n_path)
	require.Error(t, err)

	s_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.sequence`))[0]
	_, err = doc.NewZplString(s_path)
	require.Error(t, err)

	m_path := yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.mapping`))[0]
	_, err = doc.NewZplString(m_path)
	require.Error(t, err)

	i1_zsc_u, err := i1_zuns.As(reflect.TypeOf(doc.ZplUnsigned{}))
	require.NoError(t, err)
	require.IsType(t, doc.ZplUnsigned{}, i1_zsc_u)
	require.Exactly(t, uint64(i1_zsc.Value().(int64)), i1_zsc_u.Value().(uint64))

	i1_zsc_f, err := i1_zsc.As(reflect.TypeOf(doc.ZplFloat{}))
	require.NoError(t, err)
	require.IsType(t, doc.ZplFloat{}, i1_zsc_f)
	require.Exactly(t, float64(i1_zsc.Value().(int64)), i1_zsc_f.Value().(float64))

	i1_zsc_s, err := i1_zsc.As(reflect.TypeOf(doc.ZplString{}))
	require.NoError(t, err)
	require.IsType(t, doc.ZplString{}, i1_zsc_s)
	require.Exactly(t, i1_zsc.String(), i1_zsc_s.String())

	_, err = ub_zsc.As(reflect.TypeOf(doc.ZplBoolean{}))
	require.Error(t, err)
}

func TestZplScalarTypesFromBuiltins(t *testing.T) {
	b0, err := doc.NewZplBoolean(false)
	require.NoError(t, err)
	require.Exactly(t, false, b0.Value().(bool))

	b1, err := doc.NewZplBoolean(true)
	require.NoError(t, err)
	require.Exactly(t, true, b1.Value().(bool))

	_, err = doc.NewZplBoolean("not a bool")
	require.Error(t, err)

	i0, err := doc.NewZplInteger(0)
	require.NoError(t, err)
	require.Exactly(t, int64(0), i0.Value().(int64))

	i1, err := doc.NewZplInteger(int8(1))
	require.NoError(t, err)
	require.Exactly(t, int64(1), i1.Value().(int64))

	i2, err := doc.NewZplInteger(int16(2))
	require.NoError(t, err)
	require.Exactly(t, int64(2), i2.Value().(int64))

	i3, err := doc.NewZplInteger(int32(3))
	require.NoError(t, err)
	require.Exactly(t, int64(3), i3.Value().(int64))

	i4, err := doc.NewZplInteger(int64(4))
	require.NoError(t, err)
	require.Exactly(t, int64(4), i4.Value().(int64))

	_, err = doc.NewZplInteger("not an int")
	require.Error(t, err)

	u0, err := doc.NewZplUnsigned(uint(0))
	require.NoError(t, err)
	require.Exactly(t, uint64(0), u0.Value().(uint64))

	u1, err := doc.NewZplUnsigned(uint8(1))
	require.NoError(t, err)
	require.Exactly(t, uint64(1), u1.Value().(uint64))

	u2, err := doc.NewZplUnsigned(uint16(2))
	require.NoError(t, err)
	require.Exactly(t, uint64(2), u2.Value().(uint64))

	u3, err := doc.NewZplUnsigned(uint32(3))
	require.NoError(t, err)
	require.Exactly(t, uint64(3), u3.Value().(uint64))

	u4, err := doc.NewZplUnsigned(uint64(4))
	require.NoError(t, err)
	require.Exactly(t, uint64(4), u4.Value().(uint64))

	_, err = doc.NewZplUnsigned("not a uint")
	require.Error(t, err)

	f3, err := doc.NewZplFloat(float32(0))
	require.NoError(t, err)
	require.Exactly(t, float64(0), f3.Value().(float64))

	f4, err := doc.NewZplFloat(float64(1))
	require.NoError(t, err)
	require.Exactly(t, float64(1), f4.Value().(float64))

	_, err = doc.NewZplFloat("not a float")
	require.Error(t, err)

	s, err := doc.NewZplString("foo")
	require.NoError(t, err)
	require.Exactly(t, "foo", s.Value())

	_, err = doc.NewZplString(false)
	require.Error(t, err)
}

func TestZplScalarTypesUninitialized(t *testing.T) {
	var b doc.ZplBoolean
	require.Exactly(t, nil, b.Value())
	require.Exactly(t, "", b.String())

	var i doc.ZplInteger
	require.Exactly(t, nil, i.Value())
	require.Exactly(t, "", i.String())

	var u doc.ZplUnsigned
	require.Exactly(t, nil, u.Value())
	require.Exactly(t, "", u.String())

	var f doc.ZplFloat
	require.Exactly(t, nil, f.Value())
	require.Exactly(t, "", f.String())

	var s doc.ZplString
	require.Exactly(t, nil, s.Value())
	require.Exactly(t, "", s.String())
}
