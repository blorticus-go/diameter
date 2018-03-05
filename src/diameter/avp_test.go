package diameter

import (
	"fmt"
	"testing"
)

func dumpBytes(b []byte) {
	fmt.Printf("PRINTF data [%x]\n", b)
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

	encoded = []byte{
		0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x0e, 0x00, 0x01, 0x0a, 0x14, 0x1e, 0x01, 0x00, 0x00,
	}

	simpleTest(t, encoded, "Test:HostIpAddress:10.20.30.1", 14, 257, 0, true, false, []byte{0x00, 0x01, 0x0a, 0x14, 0x1e, 0x01})

	encoded = []byte{
		0x00, 0x00, 0x01, 0x0a, 0x20, 0x00, 0x00, 0x0c, 0x12, 0xab, 0x34, 0xcd,
	}

	simpleTest(t, encoded, "Test:Vendor-Id:313210061", 12, 266, 0, false, true, []byte{0x12, 0xab, 0x34, 0xcd})

	// ULA-Flags, code = 1406, vendorID = 10415, type = unsigned32, value = 33
	encoded = []byte{
		0x00, 0x00, 0x05, 0x7e, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x21,
	}

	simpleTest(t, encoded, "Test:ULA-Flags:33", 16, 1406, 10415, false, false, []byte{0x00, 0x00, 0x00, 0x21})
}
