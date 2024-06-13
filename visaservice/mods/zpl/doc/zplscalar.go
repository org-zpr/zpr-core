// Package zplscalar defines types for representing scalar values obtained from
// a ZPL source. Boolean, numeric, and string types are supported. Each value
// carries with it information about its origin in the ZPL source.
//
// All zplscalar types are immutable. Because ZPL is currently implemented in
// YAML, their "constructor" functions accept YAML node paths as arguments. Code
// that merely references zplscalar values does not need to depend on any YAML
// libraries.
package doc

import (
	"fmt"
	"math"
	"reflect"
	"strconv"

	yt "zpr.org/vsx/zpl/pp/yamltree"
)

// ZplScalar is an interface for a scalar value (boolean, number, or string)
// extracted from a ZPL source file.
type ZplScalar interface {
	// ScalarType returns the value's specific scalar type.
	Type() ZplScalarType

	// Value returns the value as a bool, int64, uint64, float64, or string
	// if the underlying concrete implementation has been initialized.
	// Otherwise it returns nil.
	Value() interface{}

	// String returns the value formatted as a string. It returns an empty
	// string if the underlying concrete implementation has not bee
	// initialized. Otherwise it returns the result of formatting the value
	// with the fmt package's "%v" verb.
	String() string

	// As returns the value represented by another ZplScalar type. Returns a
	// non-nil error if the other type cannot represent the value.
	As(other reflect.Type) (ZplScalar, error)

	// Path returns an expression for the logical path to the value through the
	// object hierarchy defined in the ZPL source. Example: "foo.bar[2].baz".
	Path() string

	// Sources returns a slice of strings identifying the value's location in
	// the ZPL source. All elements are of the form "<file>:<line>:<column>".
	// The first element gives the location of the value's actual definition in
	// its source file. Subsequent elements, if present, give locations of
	// indirect references to the value, e.g., "$<symbol>" references or
	// "$include" directives.
	Sources() []string
}

// ZplNumber is an interface for a numeric value (integer, unsigned integer,
// float) extracted from a ZPL source file. ZplNumber is a specialization of
// ZplScalar.
type ZplNumber interface {
	ZplScalar

	// AsInt64 returns the value as an int64. It returns a non-nil error if the
	// value cannot be represented exactly as an int64.
	AsInt64() (int64, error)

	// AsUint64 returns the value as a uint64. It returns a non-nil error if the
	// value cannot be represented exactly as a uint64.
	AsUint64() (uint64, error)

	// AsFloat64 returns the value as a float64. It returns a non-nil error if
	// the value is an integer that cannot be represented exactly as a float64.
	AsFloat64() (float64, error)
}

// ZplScalarType is an enumeration of value types for ZplScalar.
type ZplScalarType int

const (
	ZplUnsetScalarType ZplScalarType = iota
	ZplBooleanType
	ZplIntegerType
	ZplUnsignedType
	ZplFloatType
	ZplStringType
)

// String returns the scalar type as a short string ("boolean", "integer", ...).
func (t ZplScalarType) String() string {
	switch t {
	case ZplBooleanType:
		return "boolean"
	case ZplIntegerType:
		return "integer"
	case ZplUnsignedType:
		return "unsigned"
	case ZplFloatType:
		return "float"
	case ZplStringType:
		return "string"
	default:
		return fmt.Sprintf("<undefined ZPL scalar type %d>", t)
	}
}

// ZplBoolean is a ZplScalar implementation that represents boolean values.
type ZplBoolean struct {
	yamlScalar
}

func (_ ZplBoolean) Type() ZplScalarType {
	return ZplBooleanType
}

// AsBool returns the value as a bool.
func (b ZplBoolean) AsBool() bool {
	return b.value.(bool)
}

// ZplInteger is a ZplNumber implementation that representes int64 values.
type ZplInteger struct {
	yamlScalar
}

func (_ ZplInteger) Type() ZplScalarType {
	return ZplIntegerType
}

// ZplUnsigned is a ZplNumber implementation that representes uint64 values.
type ZplUnsigned struct {
	yamlScalar
}

func (_ ZplUnsigned) Type() ZplScalarType {
	return ZplUnsignedType
}

// ZplFloat is a ZplNumber implementation that representes float64 values.
type ZplFloat struct {
	yamlScalar
}

func (_ ZplFloat) Type() ZplScalarType {
	return ZplFloatType
}

// ZplString is a ZplScalar implementation that represents strings.
type ZplString struct {
	yamlScalar
}

func (_ ZplString) Type() ZplScalarType {
	return ZplStringType
}

// AsString returns the value as a string.
func (s ZplString) AsString() string {
	return s.value.(string)
}

func (s *ZplString) Empty() bool {
	if str, ok := s.value.(string); !ok {
		return true // cast failed
	} else {
		return str == ""
	}
}

// NewZplScalar creates a new ZplScalar value from a YAML node. The underlying
// concrete type of the returned value depends on the node's tag as identified
// by the YAML parser: "!!bool" produces a ZplBoolean, "!!int" a ZplInteger or
// (for values in the range 2^63 and 2^64 - 1, inclusive) a ZplUnsigned,
// "!!float" a ZplFLoat, and any other tag a ZplString. The argument must be a
// valid path from the YAML source's root node to the target node, which itself
// must be a scalar node. Otherwise, or if an attempt to parse a boolean or
// numeric value fails, then a non-nil error is returned.
func NewZplScalar(path []yt.Node) (ZplScalar, error) {
	if leaf, err := scalarLeaf(path); err != nil {
		return nil, err
	} else {
		switch leaf.Tag() {
		case "!!bool":
			return NewZplBoolean(path)
		case "!!int":
			i, ierr := NewZplInteger(path)
			if ierr != nil {
				if u, uerr := NewZplUnsigned(path); uerr == nil {
					return u, nil
				}
			}
			return i, ierr
		case "!!float":
			return NewZplFloat(path)
		default:
			return NewZplString(path)
		}
	}
}

// NewZplBoolean creates a new ZplBoolean value from a boolean-valued YAML node
// or a simple bool value. It requires the argument's dynamic type to be either
// []yt.Node or bool. In the first case it interprets the argument as a path to
// a target node the same way NewZplScalar does, except that it ignores the
// target node's YAML tag and unconditionally parses its string value as a bool.
// In the second case it sets the new ZplBoolean's value to the argument and its
// origin information to dummy values not associated with any external YAML
// source. It returns a non-nil error value on failure.
func NewZplBoolean(input interface{}) (ZplBoolean, error) {
	switch v := input.(type) {
	case []yt.Node:
		if leaf, err := scalarLeaf(v); err != nil {
			return ZplBoolean{}, err
		} else {
			leafText := leaf.Value().(string)
			if b, err := strconv.ParseBool(leafText); err != nil {
				return ZplBoolean{}, yt.PathErrorf(v, "cannot parse as boolean: %q", leafText)
			} else {
				return ZplBoolean{yamlScalar{v, b}}, nil
			}
		}
	case bool:
		if node, err := syntheticScalarNode(v); err != nil {
			return ZplBoolean{}, err
		} else {
			return NewZplBoolean([]yt.Node{node})
		}
	default:
		return ZplBoolean{}, fmt.Errorf("failed to create ZplBoolean: unsupported value type: %#v", v)
	}
}

// MustNewZplBoolean create a  ZplBoolean from an actual boolean.
func MustNewZplBoolean(bv bool) ZplBoolean {
	z, err := NewZplBoolean(bv)
	if err != nil {
		panic(err)
	}
	return z
}

// NewZplInteger creates a new ZplInteger value from an integer-valued YAML node
// or a simple integer value. It requires the argument's dynamic type to be
// either []yt.Node or a built-in integer type (int, int8, int16, int32, or
// int64). In the first case it interprets the argument as a path to a target
// node the same way NewZplScalar does, except that it ignores the target node's
// YAML tag and unconditionally parses its string value as an int64. In the
// second case it sets the new ZplInteger's value to the argument and its origin
// information is to dummy values not associated with any external YAML source.
// It returns a non-nil error value on failure.
func NewZplInteger(input interface{}) (ZplInteger, error) {
	switch v := input.(type) {
	case []yt.Node:
		if leaf, err := scalarLeaf(v); err != nil {
			return ZplInteger{}, err
		} else {
			leafText := leaf.Value().(string)
			if f, err := strconv.ParseInt(leafText, 10, 64); err != nil {
				return ZplInteger{}, yt.PathErrorf(v, "cannot parse as int64: %q", leafText)
			} else {
				return ZplInteger{yamlScalar{v, f}}, nil
			}
		}
	case int, int8, int16, int32, int64:
		if node, err := syntheticScalarNode(input); err != nil {
			return ZplInteger{}, err
		} else {
			return NewZplInteger([]yt.Node{node})
		}
	default:
		return ZplInteger{}, fmt.Errorf("failed to create ZplInteger: unsupported value type: %#v", v)
	}
}

func (z ZplInteger) AsInt64() (int64, error) {
	return z.Value().(int64), nil
}

func (z ZplInteger) AsUint64() (uint64, error) {
	i, _ := z.AsInt64()
	if i < 0 {
		return 0, ZplScalarErrorf(z, "cannot represent as uint64: %v", i)
	}
	return uint64(i), nil
}

func (z ZplInteger) AsFloat64() (float64, error) {
	i, _ := z.AsInt64()
	f := float64(i)
	if int64(f) != i {
		return 0, ZplScalarErrorf(z, "cannot represent exactly as float64: %v", i)
	}
	return f, nil
}

// NewZplUnsigned creates a new ZplUnsigned value from an integer-valued YAML
// node or a simple unsigned integer value. It requires the argument's dynamic
// type to be either []yt.Node or a built-in integer type (uint, uint8, uint16,
// uint32, or uint64). In the first case it interprets the argument as a path to
// a target node the same way NewZplScalar does, except that it ignores the
// target node's YAML tag and unconditionally parses its string value as a
// uint64. In the second case it sets the new ZplUnsigned's value to the
// argument and its origin information to dummy values not associated with any
// external YAML source. It returns a non-nil error value on failure.
func NewZplUnsigned(input interface{}) (ZplUnsigned, error) {
	switch v := input.(type) {
	case []yt.Node:
		if leaf, err := scalarLeaf(v); err != nil {
			return ZplUnsigned{}, err
		} else {
			leafText := leaf.Value().(string)
			if f, err := strconv.ParseUint(leafText, 10, 64); err != nil {
				return ZplUnsigned{}, yt.PathErrorf(v, "cannot parse as uint64: %q", leafText)
			} else {
				return ZplUnsigned{yamlScalar{v, f}}, nil
			}
		}
	case uint, uint8, uint16, uint32, uint64:
		if node, err := syntheticScalarNode(input); err != nil {
			return ZplUnsigned{}, err
		} else {
			return NewZplUnsigned([]yt.Node{node})
		}
	case int:
		if v < 0 {
			return ZplUnsigned{}, fmt.Errorf("failed to create ZplUnsigned: not a non-negative integer: %v", v)
		}
		if node, err := syntheticScalarNode(v); err != nil {
			return ZplUnsigned{}, err
		} else {
			return NewZplUnsigned([]yt.Node{node})
		}
	default:
		return ZplUnsigned{}, fmt.Errorf("failed to create ZplUnsigned: unsupported value type: %#v", v)
	}
}

func MustNewZplUnsigned(i uint64) ZplUnsigned {
	ui, err := NewZplUnsigned(i)
	if err != nil {
		panic(err)
	}
	return ui
}

func (z ZplUnsigned) AsInt64() (int64, error) {
	u, _ := z.AsUint64()
	if u > math.MaxInt64 {
		return 0, ZplScalarErrorf(z, "cannot represent as int64: %v", u)
	}
	return int64(u), nil
}

func (z ZplUnsigned) AsUint64() (uint64, error) {
	return z.Value().(uint64), nil
}

func (z ZplUnsigned) AsFloat64() (float64, error) {
	u, _ := z.AsUint64()
	f := float64(u)
	if uint64(f) != u {
		return 0, ZplScalarErrorf(z, "cannot represent exactly as float64: %v", u)
	}
	return f, nil
}

// NewZplFloat creates a new ZplFloat value from an integer-valued YAML node
// or a simple floating-point value. It requires the argument's dynamic type to
// be either []yt.Node or a built-in floating-point type (float32 or float64).
// In the first case it interprets the argument as a path to a target node the
// same way NewZplScalar does, except that it ignores the target node's YAML tag
// and unconditionally parses its string value as an int64. In the second case
// it sets the new ZplFloat's value to the argument and its origin information
// to dummy values not associated with any external YAML source. It returns a
// non-nil error value on failure.
func NewZplFloat(input interface{}) (ZplFloat, error) {
	switch v := input.(type) {
	case []yt.Node:
		if leaf, err := scalarLeaf(v); err != nil {
			return ZplFloat{}, err
		} else {
			leafText := leaf.Value().(string)
			if f, err := strconv.ParseFloat(leafText, 64); err != nil {
				return ZplFloat{}, yt.PathErrorf(v, "cannot parse as float64: %q", leafText)
			} else {
				return ZplFloat{yamlScalar{v, f}}, nil
			}
		}
	case float32, float64:
		if node, err := syntheticScalarNode(input); err != nil {
			return ZplFloat{}, err
		} else {
			return NewZplFloat([]yt.Node{node})
		}
	default:
		return ZplFloat{}, fmt.Errorf("failed to create ZplFloat: unsupported value type: %#v", v)
	}
}

// May loose some precision
func (z ZplFloat) AsInt64() (int64, error) {
	f, _ := z.AsFloat64()
	i := int64(f)
	if math.Abs(f) > math.MaxInt64 || float64(i) != f {
		return 0, ZplScalarErrorf(z, "cannot represent as int64: %v", f)
	}
	return int64(f), nil
}

// May loose some precision
func (z ZplFloat) AsUint64() (uint64, error) {
	f, _ := z.AsFloat64()

	if f < 0 {
		return 0, ZplScalarErrorf(z, "cannot represent negative float as uint64: %v", f)
	}

	// Proceed only if the float is pretty close to an integer.
	intf := math.Round(f)
	if math.Abs(f-intf) > 0.000000001 {
		return 0, ZplScalarErrorf(z, "cannot represent float as uint64: %v", f)
	}

	if intf > math.MaxFloat64 {
		return 0, ZplScalarErrorf(z, "cannot represent as uint64: %v", f)
	}

	u := uint64(intf)
	if float64(u) != f {
		return 0, ZplScalarErrorf(z, "cannot represent as uint64: %v", f)
	}
	return u, nil
}

func (z ZplFloat) AsFloat64() (float64, error) {
	return z.Value().(float64), nil
}

// NewZplString creates a new ZplString value from an integer-valued YAML node
// or a simple string value. It requires the argument's dynamic type to be
// either []yt.Node or string. In the first case it interprets the argument as
// a path to a target node the same way NewZplScalar does, except that it
// ignores the target node's YAML tag and simply save the node's string value.
// In the second case it sets the new ZplString's value to the argument and its
// origin information to dummy values not associated with any external YAML
// source. It returns a non-nil error value on failure.
func NewZplString(input interface{}) (ZplString, error) {
	switch v := input.(type) {
	case []yt.Node:
		if leaf, err := scalarLeaf(v); err != nil {
			return ZplString{}, err
		} else {
			return ZplString{yamlScalar{v, leaf.Value().(string)}}, nil
		}
	case string:
		if node, err := syntheticScalarNode(input); err != nil {
			return ZplString{}, err
		} else {
			return NewZplString([]yt.Node{node})
		}
	default:
		return ZplString{}, fmt.Errorf("failed to create ZplString: unsupported value type: %#v", v)
	}
}

// MustNewZplString is just like NewZplString but panics if construction fails.
func MustNewZplString(input interface{}) ZplString {
	z, err := NewZplString(input)
	if err != nil {
		panic(err)
	}
	return z
}

// Returns an error associated with a ZplScalar value. Unless the value is of
// some foreign implementation, the error includes information about the value's
// origin in the YAML source.
func ZplScalarErrorf(z ZplScalar, format string, args ...interface{}) error {
	switch v := z.(type) {
	case ZplBoolean:
		return yt.PathErrorf(v.path, format, args...)
	case ZplInteger:
		return yt.PathErrorf(v.path, format, args...)
	case ZplUnsigned:
		return yt.PathErrorf(v.path, format, args...)
	case ZplFloat:
		return yt.PathErrorf(v.path, format, args...)
	case ZplString:
		return yt.PathErrorf(v.path, format, args...)
	default:
		return fmt.Errorf(format, args...) // foreign implementation
	}
}

// A YAML scalar.
type yamlScalar struct {
	path  []yt.Node   // path from root to scalar (leaf) node
	value interface{} // leaf value as a bool, int64, uint64, float64, or string
}

// Returns the value of a YAML scalar as a bool, float64, or string (or as
// nil if the scalar is uninitialized).
func (y yamlScalar) Value() interface{} {
	return y.value
}

// Returns a path expression for a YAML scalar's definition in its YAML source.
// Panics if underlying node path is invalid.
func (y yamlScalar) Path() string {
	return yt.PathExpressionOk(y.path) // validated at creation
}

// Returns the source locations for a YAML scalar.
func (y yamlScalar) Sources() []string {
	sources := make([]string, 0, len(yt.PathSources(y.path)))
	for _, s := range yt.PathSources(y.path) {
		file := s.File
		if file == "" {
			file = "?"
		}
		sources = append(sources, fmt.Sprintf("%s:%d:%d", file, s.Line, s.Column))
	}
	return sources
}

// Returns the value of a YAML scalar formatted as a string.
func (y yamlScalar) String() string {
	if y.value == nil {
		return ""
	} else {
		return fmt.Sprintf("%v", y.value)
	}
}

// Returns the leaf node of a node path if it is a scalar node.
func scalarLeaf(path []yt.Node) (yt.Node, error) {
	if _, err := yt.PathExpression(path); err != nil {
		return nil, err // invalid path
	} else {
		last := path[len(path)-1]
		if last.Kind() != yt.ScalarKind {
			return nil, yt.PathErrorf(path, "not a scalar node: %v", last)
		}
		return last, nil
	}
}

func (y yamlScalar) As(targetType reflect.Type) (ZplScalar, error) {
	switch targetType {
	case reflect.TypeOf(ZplBoolean{}):
		return NewZplBoolean(y.path)
	case reflect.TypeOf(ZplInteger{}):
		return NewZplInteger(y.path)
	case reflect.TypeOf(ZplUnsigned{}):
		return NewZplUnsigned(y.path)
	case reflect.TypeOf(ZplFloat{}):
		return NewZplFloat(y.path)
	case reflect.TypeOf(ZplString{}):
		return NewZplString(y.path)
	default:
		return nil, fmt.Errorf("unsupported target type for conversion: %v", targetType)
	}
}

// Creates and returns a new YAML node that is not associated with any external
// YAML source. The argument becomes the new node's value. It must either be nil
// or have a dynamic type of bool, integer, float, or string.
func syntheticScalarNode(nodeValue interface{}) (yt.Node, error) {
	var node yt.Node
	node, _ = yt.ReadYamlFromString("dummy", "<internal>")
	if node, err := yt.ReplaceNodeValue(node, nodeValue); err != nil {
		return nil, err
	} else if node.Kind() != yt.ScalarKind {
		return nil, fmt.Errorf("attempt to create synthetic scalar node with non-scalar content: %v", nodeValue)
	} else {
		return node, nil
	}
}
