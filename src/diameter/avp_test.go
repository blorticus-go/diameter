package diameter

// import (
// 	"bytes"
// 	"fmt"
// 	"net"
// 	"testing"
// )
//
// func dumpBytes(b []byte) {
// 	fmt.Printf("PRINTF data [%x]\n", b)
// }
// func TestUnsigned32(t *testing.T) {
// 	data := uint32(1273828983)
// 	// mandatory true
// 	a := NewAVP(AvpOriginStateID, true, false, nil, data)
// 	if a.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", a.Flags, 0x40)
// 	}
// 	b := a.Encode()
// 	length := 4 + avpHeaderLength
// 	if len(b) != length {
// 		t.Errorf("length %d, expected %d", len(b), 12)
// 	}
// 	c := DecodeAVP(b)
// 	if data != c.Typed.(uint32) {
// 		t.Errorf("Got address [%x], expected [%x]", c.Typed, data)
// 	}
// }
//
// func TestDiamIdent(t *testing.T) {
// 	data := "eap.testbed.aaa"
// 	// mandatory true
// 	a := NewAVP(AvpOriginRealm, true, false, nil, data)
// 	if a.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", a.Flags, 0x40)
// 	}
// 	length := len(data) + avpHeaderLength
// 	if a.Length != length {
// 		t.Errorf("length %d, expected %d", a.Length, length)
// 	}
// 	b := a.Encode()
// 	if len(b) != a.PaddedLength {
// 		t.Errorf("length %d, expected %d", len(b), a.PaddedLength)
// 	}
//
// 	// Origin-Realm: Code = 296, Flags = Mandatory, Len = 23, Val = eap.testbed.aaa<null>
// 	rawBytes := []byte{0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x17, 0x65,
// 		0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x62, 0x65, 0x64, 0x2e, 0x61,
// 		0x61, 0x61, 0x00}
// 	if !bytes.Equal(b, rawBytes) {
// 		t.Errorf("Got [%x], expected [%x]", b, rawBytes)
// 	}
// 	c := DecodeAVP(rawBytes)
// 	if c.Typed != data {
// 		t.Errorf("Got address [%s], expected [%s]", c.Typed, data)
// 	}
// }
//
// func TestUTF8String(t *testing.T) {
// 	data := "freeDiameter"
// 	// mandatory true
// 	a := NewAVP(AvpProductName, false, false, nil, data)
// 	if a.Flags != 0x00 {
// 		t.Errorf("flags %x, expected %x", a.Flags, 0x00)
// 	}
// 	length := len(data) + avpHeaderLength
// 	if a.Length != length {
// 		t.Errorf("length %d, expected %d", a.Length, length)
// 	}
// 	b := a.Encode()
// 	if len(b) != a.PaddedLength {
// 		t.Errorf("length %d, expected %d", len(b), a.PaddedLength)
// 	}
// 	rawBytes := []byte{0x00, 0x00, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x14, 0x66,
// 		0x72, 0x65, 0x65, 0x44, 0x69, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72}
// 	if !bytes.Equal(b, rawBytes) {
// 		t.Errorf("Got [%x], expected [%x]", b, rawBytes)
// 	}
// 	c := DecodeAVP(rawBytes)
// 	if c.Typed != data {
// 		t.Errorf("Got string [%s], expected [%s]", c.Typed, data)
// 	}
// }
//
// func TestGrouped(t *testing.T) {
// 	// mandatory true
// 	a := NewAVP(AvpSubscriptionIDType, true, false, nil, uint32(1))
// 	b := NewAVP(AvpSubscriptionIDData, true, false, nil, "340019702747508")
// 	data := []*AVP{a, b}
//
// 	if a.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", a.Flags, 0x40)
// 	}
// 	if b.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", b.Flags, 0x40)
// 	}
// 	c := NewAVP(AvpSubscriptionID, true, false, nil, data)
// 	if c.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", c.Flags, 0x40)
// 	}
//
// 	d := c.Encode()
// 	rawBytes := []byte{0x00, 0x00, 0x01, 0xbb, 0x40, 0x00, 0x00, 0x2c, 0x00,
// 		0x00, 0x01, 0xc2, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00,
// 		0x00, 0x01, 0xbc, 0x40, 0x00, 0x00, 0x17, 0x33, 0x34, 0x30, 0x30, 0x31,
// 		0x39, 0x37, 0x30, 0x32, 0x37, 0x34, 0x37, 0x35, 0x30, 0x38, 0x00}
// 	if !bytes.Equal(d, rawBytes) {
// 		t.Errorf("Got [%x]\n    expected [%x]", d, rawBytes)
// 	}
// 	e := DecodeAVP(rawBytes)
// 	if len(e.Typed.([]*AVP)) != len(data) {
// 		t.Errorf("Got data length [%d], expected [%d]", len(e.Typed.([]*AVP)), len(data))
// 	}
// }
//
// func TestAddressV4(t *testing.T) {
// 	data := "192.168.105.30"
// 	dataIP := net.ParseIP(data)
// 	// mandatory true
// 	a := NewAVP(AvpHostIPAddress, true, false, nil, data)
// 	if a.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", a.Flags, 0x40)
// 	}
// 	length := 6 + avpHeaderLength
// 	if a.Length != length {
// 		t.Errorf("length %d, expected %d", a.Length, length)
// 	}
// 	b := a.Encode()
// 	if len(b) != a.PaddedLength {
// 		t.Errorf("length %d, expected %d", len(b), a.PaddedLength)
// 	}
// 	rawBytes := []byte{0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x0e, 0x00, 0x01,
// 		0xc0, 0xa8, 0x69, 0x1e, 0x00, 0x00}
// 	if !bytes.Equal(b, rawBytes) {
// 		t.Errorf("Got [%x], expected [%x]", b, rawBytes)
// 	}
//
// 	c := DecodeAVP(rawBytes)
// 	if !dataIP.Equal(c.Typed.(net.IP)) {
// 		t.Errorf("Got address [%x], expected [%x]", c.Typed, dataIP)
// 	}
// }
//
// func TestAddressV6(t *testing.T) {
// 	data := "fde4:2c6e:55c4:105:a00:27ff:fef0:a170"
// 	dataIP := net.ParseIP(data)
// 	// mandatory true
// 	a := NewAVP(AvpHostIPAddress, true, false, nil, data)
// 	if a.Flags != 0x40 {
// 		t.Errorf("flags %x, expected %x", a.Flags, 0x40)
// 	}
// 	length := 18 + avpHeaderLength
// 	if a.Length != length {
// 		t.Errorf("length %d, expected %d", a.Length, length)
// 	}
// 	b := a.Encode()
// 	if len(b) != a.PaddedLength {
// 		t.Errorf("length %d, expected %d", len(b), a.PaddedLength)
// 	}
// 	rawBytes := []byte{0x00, 0x00, 0x01, 0x01, 0x40, 0x00, 0x00, 0x1a, 0x00,
// 		0x02, 0xfd, 0xe4, 0x2c, 0x6e, 0x55, 0xc4, 0x01, 0x05,
// 		0x0a, 0x00, 0x27, 0xff, 0xfe, 0xf0, 0xa1, 0x70, 0x00,
// 		0x00}
// 	if !bytes.Equal(b, rawBytes) {
// 		t.Errorf("Got [%x], expected [%x]", b, rawBytes)
// 	}
// 	c := DecodeAVP(rawBytes)
// 	if !dataIP.Equal(c.Typed.(net.IP)) {
// 		t.Errorf("Got address [%x], expected [%x]", c.Typed, dataIP)
// 	}
//
// }
