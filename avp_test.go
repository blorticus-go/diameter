package diameter

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func dumpBytes(b []byte) {
	fmt.Printf("PRINTF data [%x]\n", b)
}

type simpleAvpDecodeTestAttributes struct {
	encodedBytes       []byte
	length             int
	code               uint32
	vendorID           uint32
	mandatoryFlagValue bool
	protectedFlagValue bool
	dataAsBytes        []byte
}

func simpleTest(t *testing.T, encoded []byte, testname string, length int, code uint32, vendorID uint32, mandatory bool, protected bool, data []byte) {
	avp, err := DecodeAVP(encoded)

	if err != nil {
		t.Errorf("Test = %s, should not return error but does: (%s)", testname, err.Error())
	}

	if avp.Length != length {
		t.Errorf("Test = %s, avp.Length should be (%d), is (%d)", testname, length, avp.Length)
	}

	if avp.Code != code {
		t.Errorf("Test = %s, avp.Code should be (%d), is (%d)", testname, code, avp.Code)
	}

	if avp.VendorID != vendorID {
		t.Errorf("Test = %s, avp.VendorID should be (%d), is (%d)", testname, vendorID, avp.VendorID)
	}

	if avp.Mandatory != mandatory {
		t.Errorf("Test = %s, avp.Mandatory should be (%t), is (%t)", testname, mandatory, avp.Mandatory)
	}

	if avp.Protected != protected {
		t.Errorf("Test = %s, avp.Protected should be (%t), is (%t)", testname, protected, avp.Protected)
	}

	if vendorID == 0 && avp.VendorSpecific || vendorID != 0 && !avp.VendorSpecific {
		t.Errorf("Test = %s, avp.vendorID is (%d) but avp.VendorSpecific is (%t)", testname, avp.VendorID, avp.VendorSpecific)
	}

	if len(avp.Data) != len(data) {
		t.Errorf("Test = %s, encoded avp.Data length (%d) != anticipated data length (%d)", testname, len(avp.Data), len(data))
		return
	}

	for i := 0; i < len(data); i++ {
		if avp.Data[i] != data[i] {
			t.Errorf("Test = %s, byte (%d) of encoded data does not match anticipated data", testname, i)
		}
	}

	reencode := avp.Encode()

	if len(reencode) != len(encoded) {
		t.Errorf("Test = %s, avp.Encode() length is (%d) should be (%d)", testname, len(reencode), len(encoded))
	}
}

func testAvpDecode(expected simpleAvpDecodeTestAttributes) error {
	avp, err := DecodeAVP(expected.encodedBytes)

	if err != nil {
		return fmt.Errorf("should not return error but does: (%s)", err.Error())
	}

	if avp.Length != expected.length {
		return fmt.Errorf("avp.Length should be (%d), is (%d)", expected.length, avp.Length)
	}

	if avp.Code != expected.code {
		return fmt.Errorf("avp.Code should be (%d), is (%d)", expected.code, avp.Code)
	}

	if avp.VendorID != expected.vendorID {
		return fmt.Errorf("avp.VendorID should be (%d), is (%d)", expected.vendorID, avp.VendorID)
	}

	if avp.Mandatory != expected.mandatoryFlagValue {
		return fmt.Errorf("avp.Mandatory should be (%t), is (%t)", expected.mandatoryFlagValue, avp.Mandatory)
	}

	if avp.Protected != expected.protectedFlagValue {
		return fmt.Errorf("avp.Protected should be (%t), is (%t)", expected.protectedFlagValue, avp.Protected)
	}

	if expected.vendorID == 0 && avp.VendorSpecific || expected.vendorID != 0 && !avp.VendorSpecific {
		return fmt.Errorf("avp.vendorID is (%d) but avp.VendorSpecific is (%t)", avp.VendorID, avp.VendorSpecific)
	}

	if len(avp.Data) != len(expected.dataAsBytes) {
		return fmt.Errorf("encoded avp.Data length (%d) != anticipated data length (%d)", len(avp.Data), len(expected.dataAsBytes))
	}

	for i := 0; i < len(expected.dataAsBytes); i++ {
		if avp.Data[i] != expected.dataAsBytes[i] {
			return fmt.Errorf("byte (%d) of encoded data does not match anticipated data", i)
		}
	}

	reEncodedAvp := avp.Encode()

	if len(reEncodedAvp) != len(expected.encodedBytes) {
		return fmt.Errorf("avp.Encode() length is (%d) should be (%d)", len(reEncodedAvp), len(expected.encodedBytes))
	}

	return nil
}

func compareAvpValues(avp *AVP, code uint32, vendorID uint32, mandatory bool, data []byte, length int, paddedLength int) error {
	if avp == nil {
		return fmt.Errorf("AVP is nil")
	}
	if avp.Code != code {
		return fmt.Errorf("Expected AVP code (%d), but got (%d)", avp.Code, code)
	}
	if avp.VendorID != vendorID {
		return fmt.Errorf("Expected VendorID (%d), but got (%d)", avp.VendorID, vendorID)
	}
	if vendorID == 0 {
		if avp.VendorSpecific {
			return fmt.Errorf("Expected VendorSpecific attribute false, but got true")
		}
	} else {
		if !avp.VendorSpecific {
			return fmt.Errorf("Expected VendorSpecific attribute true, but got false")
		}
	}
	if avp.Mandatory != mandatory {
		return fmt.Errorf("Expected mandatory attribute (%t), but got (%t)", mandatory, avp.Mandatory)
	}
	if avp.Length != length {
		return fmt.Errorf("Expected avp length (%d), got (%d)", length, avp.Length)
	}
	if avp.PaddedLength != paddedLength {
		return fmt.Errorf("Expected avp length (%d), got (%d)", paddedLength, avp.PaddedLength)
	}
	if len(avp.Data) != len(data) {
		return fmt.Errorf("Expected data length (%d), got (%d)", len(data), len(avp.Data))
	}
	for i := 0; i < len(avp.Data); i++ {
		if avp.Data[i] != data[i] {
			return fmt.Errorf("Expected data element (%d) = %d, got = %d", i, data[i], avp.Data[i])
		}
	}

	return nil
}

type goodTypedValueTestValues struct {
	goodTypedValueToTest    interface{}
	expectedValueAsBytes    []byte
	expectedAvpLength       int
	expectedAvpPaddedLength int
}

type badTypedValueTest struct {
	badTypedValueToTest interface{}
}

func typedAvpComparisonTest(avpCode uint32, avpVendorID uint32, avpType AVPDataType, testsThatShouldSucceed []goodTypedValueTestValues, testsThatShouldFail []badTypedValueTest) error {
	for _, testCase := range testsThatShouldSucceed {
		avp, err := NewTypedAVPErrorable(avpCode, avpVendorID, false, avpType, testCase.goodTypedValueToTest)

		if err != nil {
			return fmt.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
		}

		if err = compareAvpValues(avp, avpCode, avpVendorID, false, testCase.expectedValueAsBytes, testCase.expectedAvpLength, testCase.expectedAvpPaddedLength); err != nil {
			return fmt.Errorf("On AVP comparison, got unexpected error: %s", err)
		}
	}

	for _, testCase := range testsThatShouldFail {
		if _, err := NewTypedAVPErrorable(avpCode, avpVendorID, false, avpType, testCase.badTypedValueToTest); err == nil {
			return fmt.Errorf("Expected error on passing invalid typed data for AVP, but received none")
		}
	}

	if _, err := NewTypedAVPErrorable(avpCode, avpVendorID, false, avpType, nil); err == nil {
		return fmt.Errorf("Expected error on passing nil data for AVP, but received none")
	}

	return nil
}

func TestOriginHost(t *testing.T) {
	// Origin-Host is code 264, type of DiamIdent, value for this encoding is
	// host.example.com
	encoded := []byte{
		0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x18, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	simpleTest(t, encoded, "Test:OriginHost:test.example.com", 24, 264, 0, true, false, encoded[8:])

	// same thing but one character shorter (requires padding)
	encoded = []byte{
		0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x18, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x00,
	}

	simpleTest(t, encoded, "Test:OriginHost:test.example.co", 24, 264, 0, true, false, encoded[8:])
}

func TestVendorId(t *testing.T) {
	encoded := []byte{
		0x00, 0x00, 0x01, 0x0a, 0x20, 0x00, 0x00, 0x0c, 0x12, 0xab, 0x34, 0xcd,
	}

	simpleTest(t, encoded, "Test:Vendor-Id:313210061", 12, 266, 0, false, true, []byte{0x12, 0xab, 0x34, 0xcd})
}

func TestULAFlags(t *testing.T) {
	// ULA-Flags, code = 1406, vendorID = 10415, type = unsigned32, value = 33
	encoded := []byte{
		0x00, 0x00, 0x05, 0x7e, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x21,
	}

	simpleTest(t, encoded, "Test:ULA-Flags:33", 16, 1406, 10415, false, false, []byte{0x00, 0x00, 0x00, 0x21})
}

func TestGGSNAddress(t *testing.T) {
	err := testAvpDecode(simpleAvpDecodeTestAttributes{
		encodedBytes: []byte{
			0x00, 0x00, 0x03, 0x4f,
			0x80, 0x00, 0x00, 0x12,
			0x00, 0x00, 0x27, 0xa1,
			0x00, 0x01, 0x0a, 0x14, 0x1e, 0x01, 0x00, 0x00,
		},
		vendorID:           10145,
		code:               847,
		mandatoryFlagValue: false,
		protectedFlagValue: false,
		length:             18,
		dataAsBytes:        []byte{0x00, 0x01, 0x0a, 0x14, 0x1e, 0x01},
	})

	if err != nil {
		t.Errorf("GGSNAddress with IPv4 address (10.20.31.1) error on decode test: %s", err)
	}

	err = testAvpDecode(simpleAvpDecodeTestAttributes{
		encodedBytes: []byte{
			0x00, 0x00, 0x03, 0x4f,
			0xc0, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x27, 0xa1,
			0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
		},
		vendorID:           10145,
		code:               847,
		mandatoryFlagValue: true,
		protectedFlagValue: false,
		length:             28,
		dataAsBytes:        []byte{0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34},
	})

	if err != nil {
		t.Errorf("GGSNAddress with IPv6 address (2001:db8:abcd:1::1234) error on decode test: %s", err)
	}
}

func TestTypedAvpUnsigned32(t *testing.T) {
	avp, err := NewTypedAVPErrorable(259, 0, true, Unsigned32, uint32(1000))

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		if err = compareAvpValues(avp, 259, 0, true, []byte{0x00, 0x00, 0x03, 0xe8}, 12, 12); err != nil {
			t.Errorf("On AVP comparison: %s", err)
		}
	}

	_, err = NewTypedAVPErrorable(259, 0, true, Unsigned32, uint16(1000))

	if err == nil {
		t.Errorf("Expected error on passing invalid typed data for AVP, but received none")
	}

	_, err = NewTypedAVPErrorable(259, 0, true, Unsigned32, nil)

	if err == nil {
		t.Errorf("Expected error on passing nil data for AVP, but received none")
	}
}

func TestTypedAvpUnsigned64(t *testing.T) {
	avp, err := NewTypedAVPErrorable(287, 0, true, Unsigned64, uint64(0x1f001f0011223344))

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		if err = compareAvpValues(avp, 287, 0, true, []byte{0x1f, 0x00, 0x1f, 0x00, 0x11, 0x22, 0x33, 0x44}, 16, 16); err != nil {
			t.Errorf("On AVP Comparison (value = 0x1f001f0011223344), received unexpected error = (%s)", err)
		}
	}

	avp, err = NewTypedAVPErrorable(287, 0, true, Unsigned64, uint64(0))

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		if err = compareAvpValues(avp, 287, 0, true, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 16, 16); err != nil {
			t.Errorf("On AVP Comparison (value = 0), received unexpected error = (%s)", err)
		}
	}

	_, err = NewTypedAVPErrorable(287, 0, true, Unsigned64, int64(1000))

	if err == nil {
		t.Errorf("When using int64() for Unsigned64 type, expected error, but got none")
	}

	_, err = NewTypedAVPErrorable(287, 0, true, Unsigned64, uint32(1000))

	if err == nil {
		t.Errorf("Expected error on passing invalid typed data for AVP, but received none")
	}

	_, err = NewTypedAVPErrorable(287, 0, true, Unsigned64, nil)

	if err == nil {
		t.Errorf("Expected error on passing nil data for AVP, but received none")
	}
}

func TestTypedAvpIPv4(t *testing.T) {
	avp, err := NewTypedAVPErrorable(257, 0, false, Address, net.IPv4(10, 11, 12, 255))

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		if err = compareAvpValues(avp, 257, 0, false, []byte{0x00, 0x01, 0x0a, 0x0b, 0x0c, 0xff}, 14, 16); err != nil {
			t.Errorf("On AVP comparison: %s", err)
		}
	}

	_, err = NewTypedAVPErrorable(257, 0, false, Address, uint16(1000))

	if err == nil {
		t.Errorf("Expected error on passing invalid typed data for AVP, but received none")
	}

	_, err = NewTypedAVPErrorable(257, 0, false, Address, nil)

	if err == nil {
		t.Errorf("Expected error on passing nil data for AVP, but received none")
	}
}

func TestTypedAvpIPv6(t *testing.T) {
	avp, err := NewTypedAVPErrorable(257, 0, false, Address, net.ParseIP("2006:abcd:1:1::10"))

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		if err = compareAvpValues(avp, 257, 0, false, []byte{0x00, 0x02, 0x20, 0x06, 0xab, 0xcd, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10}, 26, 28); err != nil {
			t.Errorf("On AVP comparison: %s", err)
		}
	}

	_, err = NewTypedAVPErrorable(257, 0, false, Address, uint16(1000))

	if err == nil {
		t.Errorf("Expected error on passing invalid typed data for AVP, but received none")
	}

	_, err = NewTypedAVPErrorable(257, 0, false, Address, nil)

	if err == nil {
		t.Errorf("Expected error on passing nil data for AVP, but received none")
	}
}

func TestTypedAvpNetAddr(t *testing.T) {
	v4NetAddr, _ := net.ResolveIPAddr("ip4", "192.168.10.1")
	v6NetAddr, _ := net.ResolveIPAddr("ip6", "fd00:abcd:0:1234:afff::1")

	if err := typedAvpComparisonTest(50, 0, Address,
		// Address can be net.IPAddr or *net.IPAddr (or IP.Addr, but that is tested above)
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    *v4NetAddr,
				expectedValueAsBytes:    []byte{0x00, 0x01, 0xc0, 0xa8, 0x0a, 0x01},
				expectedAvpLength:       14,
				expectedAvpPaddedLength: 16,
			},
			{
				goodTypedValueToTest:    *v6NetAddr,
				expectedValueAsBytes:    []byte{0x00, 0x02, 0xfd, 0x00, 0xab, 0xcd, 0, 0, 0x12, 0x34, 0xaf, 0xff, 0, 0, 0, 0, 0, 0x1},
				expectedAvpLength:       26,
				expectedAvpPaddedLength: 28,
			},
			{
				goodTypedValueToTest:    v4NetAddr,
				expectedValueAsBytes:    []byte{0x00, 0x01, 0xc0, 0xa8, 0x0a, 0x01},
				expectedAvpLength:       14,
				expectedAvpPaddedLength: 16,
			},
			{
				goodTypedValueToTest:    v6NetAddr,
				expectedValueAsBytes:    []byte{0x00, 0x02, 0xfd, 0x00, 0xab, 0xcd, 0, 0, 0x12, 0x34, 0xaf, 0xff, 0, 0, 0, 0, 0, 0x1},
				expectedAvpLength:       26,
				expectedAvpPaddedLength: 28,
			},
		},
		[]badTypedValueTest{},
	); err != nil {
		t.Errorf("%s", err)
	}
}

func TestTypedAvpGrouped(t *testing.T) {
	avp, err := NewTypedAVPErrorable(260, 16777270, true, Grouped, []*AVP{
		NewAVP(266, 0, true, []byte{0, 0, 0x7e, 0xd9}),
		NewAVP(258, 0, false, []byte{0x01, 0x00, 0x00, 0x36}),
	})

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		if err = compareAvpValues(avp, 260, 16777270, true, []byte{
			0x00, 0x00, 0x01, 0x0a, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x7e, 0xd9,
			0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x36,
		}, 36, 36); err != nil {
			t.Errorf("On AVP comparison: %s", err)
		}
	}

	_, err = NewTypedAVPErrorable(260, 16777270, true, Grouped, uint32(1000))

	if err == nil {
		t.Errorf("Expected error on passing invalid typed data for AVP, but received none")
	}

	_, err = NewTypedAVPErrorable(260, 16777270, true, Grouped, []byte{1, 2, 3, 4})

	if err == nil {
		t.Errorf("Expected error on passing nil data for AVP, but received none")
	}
}

func TestDiamURI(t *testing.T) {
	avp, err := NewTypedAVPErrorable(282, 0, false, DiamURI, "aaa://host.example.com;transport=tcp")

	if err != nil {
		t.Errorf("Unexpected error on NewTypedAVPErrorable: %s", err)
	} else {
		expectedDataValue := []byte{0x61, 0x61, 0x61, 0x3a, 0x2f, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3b, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x3d, 0x74, 0x63, 0x70}
		if err = compareAvpValues(avp, 282, 0, false, expectedDataValue, 44, 44); err != nil {
			t.Errorf("On AVP comparison: %s", err)
		}
	}

	_, err = NewTypedAVPErrorable(282, 0, false, DiamURI, uint16(1000))

	if err == nil {
		t.Errorf("Expected error on passing invalid typed data for AVP, but received none")
	}

	_, err = NewTypedAVPErrorable(282, 0, false, DiamURI, nil)

	if err == nil {
		t.Errorf("Expected error on passing nil data for AVP, but received none")
	}
}

func TestUTF8String(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, UTF8String,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    "foo",
				expectedValueAsBytes:    []byte{0x66, 0x6f, 0x6f},
				expectedAvpLength:       11,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    []byte{0x66, 0x6f, 0x6f},
				expectedValueAsBytes:    []byte{0x66, 0x6f, 0x6f},
				expectedAvpLength:       11,
				expectedAvpPaddedLength: 12,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func TestInteger32(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, Integer32,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    int32(0),
				expectedValueAsBytes:    []byte{0x0, 0x0, 0x0, 0x0},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    int32(-2147483648),
				expectedValueAsBytes:    []byte{0x80, 0x00, 0x00, 0x00},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    int32(2147483647),
				expectedValueAsBytes:    []byte{0x7f, 0xff, 0xff, 0xff},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
			{
				badTypedValueToTest: uint32(2130706432),
			},
			{
				badTypedValueToTest: uint32(2147483648),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func TestInteger64(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, Integer64,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    int64(0),
				expectedValueAsBytes:    []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				expectedAvpLength:       16,
				expectedAvpPaddedLength: 16,
			},
			{
				goodTypedValueToTest:    int64(-9223372036854775808),
				expectedValueAsBytes:    []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				expectedAvpLength:       16,
				expectedAvpPaddedLength: 16,
			},
			{
				goodTypedValueToTest:    int64(9223372036854775807),
				expectedValueAsBytes:    []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				expectedAvpLength:       16,
				expectedAvpPaddedLength: 16,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
			{
				badTypedValueToTest: uint64(9223372036854775808),
			},
			{
				badTypedValueToTest: uint64(9223372036854775807),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func TestFloat32(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, Float32,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    float32(0),
				expectedValueAsBytes:    []byte{0x0, 0x0, 0x0, 0x0},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    float32(0.0),
				expectedValueAsBytes:    []byte{0x00, 0x00, 0x00, 0x00},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    float32(-16635.1234),
				expectedValueAsBytes:    []byte{0xc6, 0x81, 0xf6, 0x3f},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
			{
				badTypedValueToTest: float64(0),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func TestFloat64(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, Float64,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    float64(0),
				expectedValueAsBytes:    []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				expectedAvpLength:       16,
				expectedAvpPaddedLength: 16,
			},
			{
				goodTypedValueToTest:    float64(0.0),
				expectedValueAsBytes:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				expectedAvpLength:       16,
				expectedAvpPaddedLength: 16,
			},
			{
				goodTypedValueToTest:    float64(-16635.1234),
				expectedValueAsBytes:    []byte{0xc0, 0xd0, 0x3e, 0xc7, 0xe5, 0xc9, 0x1d, 0x15},
				expectedAvpLength:       16,
				expectedAvpPaddedLength: 16,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
			{
				badTypedValueToTest: float32(0),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func TestEnumerated(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, Enumerated,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    int32(0),
				expectedValueAsBytes:    []byte{0x0, 0x0, 0x0, 0x0},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    int32(-2147483648),
				expectedValueAsBytes:    []byte{0x80, 0x00, 0x00, 0x00},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    int32(2147483647),
				expectedValueAsBytes:    []byte{0x7f, 0xff, 0xff, 0xff},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
			{
				badTypedValueToTest: uint32(2130706432),
			},
			{
				badTypedValueToTest: uint32(2147483648),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func TestOctetString(t *testing.T) {
	reallyLongByteSet := make([]byte, 2048)
	for i := 0; i < 2048; i++ {
		reallyLongByteSet[i] = byte(i)
	}

	if err := typedAvpComparisonTest(50, 0, OctetString,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    []byte{},
				expectedValueAsBytes:    []byte{},
				expectedAvpLength:       8,
				expectedAvpPaddedLength: 8,
			},
			{
				goodTypedValueToTest:    []byte{0},
				expectedValueAsBytes:    []byte{0},
				expectedAvpLength:       9,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    []byte{0xff, 0x0, 0xff},
				expectedValueAsBytes:    []byte{0xff, 0x0, 0xff},
				expectedAvpLength:       11,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    reallyLongByteSet,
				expectedValueAsBytes:    reallyLongByteSet,
				expectedAvpLength:       2056,
				expectedAvpPaddedLength: 2056,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: uint32(0),
			},
			{
				badTypedValueToTest: []int{0, 1},
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

// Time (byte[4]), IPFilter
func TestTime(t *testing.T) {
	if err := typedAvpComparisonTest(50, 0, Time,
		[]goodTypedValueTestValues{
			{
				goodTypedValueToTest:    []byte{0xe1, 0xba, 0xb6, 0x8c},
				expectedValueAsBytes:    []byte{0xe1, 0xba, 0xb6, 0x8c},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    uint32(0),
				expectedValueAsBytes:    []byte{0, 0, 0, 0},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    uint32(3787110028),
				expectedValueAsBytes:    []byte{0xe1, 0xba, 0xb6, 0x8c},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    time.Unix(1578034828, 0),
				expectedValueAsBytes:    []byte{0xe1, 0xb9, 0x65, 0x0c},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    timeStructToTimeStructPointer(time.Unix(1578034828, 0)),
				expectedValueAsBytes:    []byte{0xe1, 0xb9, 0x65, 0x0c},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC),
				expectedValueAsBytes:    []byte{0, 0, 0, 0},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
			{
				goodTypedValueToTest:    timeStructToTimeStructPointer(time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)),
				expectedValueAsBytes:    []byte{0, 0, 0, 0},
				expectedAvpLength:       12,
				expectedAvpPaddedLength: 12,
			},
		},
		[]badTypedValueTest{
			{
				badTypedValueToTest: int32(0),
			},
			{
				badTypedValueToTest: []byte{},
			},
			{
				badTypedValueToTest: []byte{0},
			},
			{
				badTypedValueToTest: []byte{0, 1},
			},
			{
				badTypedValueToTest: []byte{0, 1, 2},
			},
			{
				badTypedValueToTest: []byte{0, 1, 2, 3, 4},
			},
			{
				badTypedValueToTest: []uint32{0, 1, 2, 3},
			},
			{
				badTypedValueToTest: time.Unix(68719476736, 0),
			},
			{
				badTypedValueToTest: timeStructToTimeStructPointer(time.Unix(68719476736, 0)),
			},
			{
				badTypedValueToTest: time.Date(1899, time.December, 31, 23, 59, 59, 0, time.UTC),
			},
			{
				badTypedValueToTest: timeStructToTimeStructPointer(time.Date(1899, time.December, 31, 23, 59, 59, 0, time.UTC)),
			},
		}); err != nil {
		t.Errorf("%s", err)
	}
}

func timeStructToTimeStructPointer(t time.Time) *time.Time {
	return &t
}
