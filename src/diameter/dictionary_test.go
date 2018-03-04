package diameter

import (
	"bytes"
	"net"
	"testing"
)

var dict *Dictionary

func init() {
	dict, _ = ReadYamlDictionaryFile("../../dictionaries/diameter_base.yaml")
	if dict == nil {
		panic("dictionary not initialized")
	}
}

func TestDictReading(t *testing.T) {
	if dict == nil {
		t.Errorf("Dict is nil")
	}
}

var avpTests = []struct {
	name          string
	datatype      AVPAttributeType
	data          interface{}
	mandatory     bool
	protected     bool
	flags         byte // expected
	length        int  // expected data length
	padded_length int  // expected data length
	raw           []byte
}{
	{"Origin-State-Id", Unsigned32, uint32(1273828983), true, false, 0x40, 4 + avpHeaderLength, 4 + avpHeaderLength, nil},
	{"Host-IP-Address", Address, "fde4:2c6e:55c4:105:a00:27ff:fef0:a170", true, false, 0x40, 18 + avpHeaderLength, 20 + avpHeaderLength,
		[]byte{0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x1a, 0x00,
			0x02, 0xfd, 0xe4, 0x2c, 0x6e, 0x55, 0xc4, 0x01, 0x05,
			0x0a, 0x00, 0x27, 0xff, 0xfe, 0xf0, 0xa1, 0x70, 0x00,
			0x00}},
	{"Host-IP-Address", Address, "192.168.105.30", true, false, 0x40, 6 + avpHeaderLength, 8 + avpHeaderLength,
		[]byte{0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x0e, 0x00, 0x01,
			0xc0, 0xa8, 0x69, 0x1e, 0x00, 0x00}},
	{"Product-Name", UTF8String, "freeDiameter", false, false, 0x00, 12 + avpHeaderLength, 12 + avpHeaderLength,
		[]byte{0x00, 0x00, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x14, 0x66,
			0x72, 0x65, 0x65, 0x44, 0x69, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72}},
	{"Origin-Realm", DiamIdent, "eap.testbed.aaa", true, false, 0x40, 15 + avpHeaderLength, 16 + avpHeaderLength,
		[]byte{0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x17, 0x65,
			0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x62, 0x65, 0x64, 0x2e, 0x61,
			0x61, 0x61, 0x00}},
}

func TestDataConversionUsingDictionary(t *testing.T) {
	if dict == nil {
		t.Errorf("dictionary not initialized")
	}
	for _, tt := range avpTests {
		avp := dict.AVPWithFlags(tt.name,
			map[string]bool{"mandatory": tt.mandatory, "protected": tt.protected},
			tt.data)
		if avp.Flags != tt.flags {
			t.Errorf("[%s] flags %x, expected %x", tt.name, avp.Flags, tt.flags)
		}
		if avp.Length != tt.length {
			t.Errorf("[%s] length %d, expected %d", tt.name, avp.Length, tt.length)
		}
		encoded := avp.Encode()
		if len(encoded) != tt.padded_length {
			t.Errorf("[%s] length %d, expected %d", tt.name, len(encoded), tt.padded_length)
		}
		if tt.raw != nil {
			if !bytes.Equal(encoded, tt.raw) {
				t.Errorf("[%s] Got [%x], expected [%x]", tt.name, encoded, tt.raw)
			}
		}
		decoded := DecodeAVP(encoded)
		switch tt.datatype {
		case Unsigned32:
			if tt.data.(uint32) != decoded.Typed.(uint32) {
				t.Errorf("Got data [%s], expected [%s]", decoded.Typed, tt.data.(uint32))
			}
		case Address:
			data_ip := net.ParseIP(tt.data.(string))
			if !data_ip.Equal(decoded.Typed.(net.IP)) {
				t.Errorf("Got data [%x], expected [%x]", decoded.Typed, data_ip)
			}
		case DiamIdent, UTF8String:
			if tt.data.(string) != decoded.Typed.(string) {
				t.Errorf("Got data [%s], expected [%s]", decoded.Typed, tt.data.(string))
			}
		}
	}
}

var msgCodeTests = []struct {
	lookupString    string
	expectedMsgCode Uint24
}{
	{"Capabilities-Exchange-Answer", 257},
	{"CEA", 257},
	{"Capabilities-Exchange-Request", 257},
	{"CER", 257},
	{"Credit-Control-Answer", 272},
	{"CCA", 272},
	{"Credit-Control-Answer", 272},
	{"CCR", 272},
	{"Non-Existent", 0},
}

func TestMsgCode(t *testing.T) {
	if dict == nil {
		t.Errorf("dictionary not initialized")
	}

	for _, set := range msgCodeTests {
		c := dict.MsgCode(set.lookupString)
		if c != set.expectedMsgCode {
			t.Errorf("For msgCodeTest lookup string [%s] expected code [%d] but got code [%d]", set.lookupString, uint(set.expectedMsgCode), uint(c))
		}
	}
}

var msgAttributesTests = []struct {
	lookupString      string
	expectNil         bool
	expectedName      string
	expectedAbbr      string
	expectedMsgCode   Uint24
	expectedIsRequest bool
}{
	{"Capabilities-Exchange-Answer", false, "Capabilities-Exchange-Answer", "CEA", 257, false},
	{"Capabilities-Exchange-Request", false, "Capabilities-Exchange-Request", "CER", 257, true},
	{"Credit-Control-Answer", false, "Credit-Control-Answer", "CCA", 272, false},
	{"Credit-Control-Request", false, "Credit-Control-Request", "CCR", 272, true},
	{"Non-Existent", true, "", "", 0, false},
}

func testMsgAttributes(t *testing.T) {
	if dict == nil {
		t.Errorf("dictionary not initialized")
	}

	for _, set := range msgAttributesTests {
		attrs := dict.MsgAttributes(set.lookupString)

		if set.expectNil {
			if attrs != nil {
				t.Errorf("Expected nil attributes for lookup string [%s] but did not get nil", set.lookupString)
			}
		} else {
			if attrs == nil {
				t.Errorf("Expected attributes for lookup string [%s] but got nil", set.lookupString)
			} else {
				if attrs.msgName != set.expectedName {
					t.Errorf("For MsgAttributes lookup string [%s] expected name to be [%s] but was [%s]", set.lookupString, set.expectedName, attrs.msgName)
				} else if attrs.msgAbbrv != set.expectedAbbr {
					t.Errorf("For MsgAttributes lookup string [%s] expected abbreviation to be [%s] but was [%s]", set.lookupString, set.expectedAbbr, attrs.msgAbbrv)
				} else if attrs.msgCode != set.expectedMsgCode {
					t.Errorf("For MsgAttributes lookup string [%s] expected code to be [%d] but was [%d]", set.lookupString, uint(set.expectedMsgCode), uint(attrs.msgCode))
				} else if attrs.msgIsRequest != set.expectedIsRequest {
					t.Errorf("For MsgAttributes lookup string [%s] expected IsRequest to be [%t] but was [%t]", set.lookupString, set.expectedIsRequest, attrs.msgIsRequest)
				}
			}
		}
	}

	// changes to the returned Attributes struct should not affect the underlying struct
	attrs := dict.MsgAttributes("ACA")

	if attrs == nil {
		t.Errorf("Failed to lookup ACA attributes from dictionary")
	}

	if attrs.msgIsRequest {
		t.Errorf("ACA in dictionary is set as a request")
	} else {
		attrs.msgIsRequest = true

		if !attrs.msgIsRequest {
			t.Errorf("Change to returned attributes for ACA did not occur")
		} else {
			attrs_again := dict.MsgAttributes("ACA")

			if attrs_again.msgIsRequest {
				t.Errorf("Change to returned attributes for ACA changed underlying ACA definition in Dictionary object")
			}
		}
	}
}
