package diameter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// AVPDataType is an enumeration of Diameter AVP types
type AVPDataType int

const (
	// Unsigned32 indicates AVP type for unsigned 32-bit integer
	Unsigned32 AVPDataType = 1 + iota
	// Unsigned64 indicates AVP type for unsigned 64-bit integer
	Unsigned64
	// Enumerated indicates AVP type for enumerated (integer)
	Enumerated
	// UTF8String indicates AVP type for UTF8String (a UTF8 encoded octet stream)
	UTF8String
	// OctetString indicates AVP type for octet string (an arbitrary octet stream)
	OctetString
	// Time indicates AVP type for time (unix epoch time as unsigned 32)
	Time
	// Address indicates AVP type for address (an IPv4 or IPv6 address with leading type qualifier)
	Address
	// DiamIdent indicates AVP type for diameter identity (an octet stream)
	DiamIdent
	// DiamURI indicates AVP type for a diameter URI (an octet stream)
	DiamURI
	// Grouped indicates AVP type for grouped (a set of AVPs)
	Grouped
)

const (
	avpProtectedFlag      = 0x20
	avpMandatoryFlag      = 0x40
	avpFlagVendorSpecific = 0x80
	avpHeaderLength       = 8
)

// these are the leading type qualifier values in an AVP value of Address type
const (
	addrIPv4 = 1
	addrIPv6 = 2
)

// AVPAttributes represents the immuatable attributes of an AVP
// type AVPAttributes struct {
// 	dataType AVPType
// 	code     uint32
// 	//	attrValues map[uint32]string
// 	VendorID uint32
// 	// If there is a “min” it means that is the minimum count.
// 	// If there is a “max” that is the maximum amount (if there is no min or max, then min=1, max=1.
// 	// If there is no max but a min, then max=<infinite>.
// 	// If there is a max but no min, then the min is 1).
// 	min int
// 	max int
// }

// TypeToAVPAttributes is an exported, unprotected map that is indexed
// by a Diameter AVP Type integer value, and points to the corresponding
// AVPAttributess, if it is defined
//var TypeToAVPAttributess = map[uint32]*AVPAttributess{}

// NewAVPAttributess is an AVPAttributes constructor.  It also adds the newly
// constructed object to the TypeToAVPAttributess map
// func NewAVPAttributes(code uint32, VendorID uint32, dataType AVPType) *AVPAttributes {
// 	d := new(AVPAttributes)
// 	d.dataType = dataType
// 	d.code = code
// 	d.VendorID = VendorID
// 	//	d.attrValues = make(map[uint32]string)
// 	//	TypeToAVPAttributes[d.code] = d
// 	return d
// }

// // NewAVPAttributesAndValue creates a new AVPAttributes and provides it with a value
// func NewAVPAttributesAndValue(name string, code uint32, VendorID uint32, type AVPType, attrValues map[uint32]string) *AVPAttributes {
// 	d := new(AVPAttributes)
// 	d.attrName = name
// 	d.type = type
// 	d.vendorID = vendorID
// 	d.code = code
// 	d.attrValues = attrValues
// 	TypeToAVPAttributes[d.code] = d
// 	return d
// }

// func (avp *AVPAttributes) clone() *AVPAttributes {
// 	ret := &AVPAttributes{dataType: avp.dataType, vendorID: avp.vendorID,
// 		code: avp.code} //, attrValues: make(map[uint32]string)}
// 	//	for k, v := range avp.attrValues {
// 	//		ret.attrValues[k] = v
// 	//	}
// 	return ret
// }

// Code returns the AVP code
// func (avp *AVPAttributes) Code() uint32 {
// 	return avp.code
// }

// Some basic AVP types with their defined attributes
// var (
// 	AvpAcctinterimInterval         = NewAVPAttributes(85, 0, Unsigned32)
// 	AvpAccountingRealtimeRequired  = NewAVPAttributes(483, 0, Enumerated)
// 	AvpAcctMultiSessionID          = NewAVPAttributes("Acct-Multi-Session-Id", 50, 0, UTF8String)
// 	AvpAccountingRecordNumber      = NewAVPAttributes("Accounting-Record-Number", 485, 0, Unsigned32)
// 	AvpAccountingRecordType        = NewAVPAttributes("Accounting-Record-Type", 480, 0, Enumerated)
// 	AvpAccountingSessionID         = NewAVPAttributes("Accounting-Session-Id", 44, 0, OctetString)
// 	AvpAccountingSubSessionID      = NewAVPAttributes("Accounting-Sub-Session-Id", 287, 0, Unsigned64)
// 	AvpAcctApplicationID           = NewAVPAttributes("Acct-Application-Id", 259, 0, Unsigned32)
// 	AvpAuthApplicationID           = NewAVPAttributes("Auth-Application-Id", 258, 0, Unsigned32)
// 	AvpAuthRequestType             = NewAVPAttributes("Auth-Request-Type", 274, 0, Enumerated)
// 	AvpAuthorizationLifetime       = NewAVPAttributes("Authorization-Lifetime", 291, 0, Unsigned32)
// 	AvpAuthGracePeriod             = NewAVPAttributes("Auth-Grace-Period", 276, 0, Unsigned32)
// 	AvpAuthSessionState            = NewAVPAttributes("Auth-Session-State", 277, 0, Enumerated)
// 	AvpReAuthRequestType           = NewAVPAttributes("Re-Auth-Request-Type", 285, 0, Enumerated)
// 	AvpClass                       = NewAVPAttributes("Class", 25, 0, OctetString)
// 	AvpDestinationHost             = NewAVPAttributes("Destination-Host", 293, 0, DiamIdent)
// 	AvpDestinationRealm            = NewAVPAttributes("Destination-Realm", 283, 0, DiamIdent)
// 	AvpDisconnectCause             = NewAVPAttributes("Disconnect-Cause", 273, 0, Enumerated)
// 	AvpE2eSequence                 = NewAVPAttributes("E2E-Sequence", 300, 0, Grouped)
// 	AvpEapPayload                  = NewAVPAttributes("EAP-Payload", 462, 0, OctetString)
// 	AvpErrorMessage                = NewAVPAttributes("Error-Message", 281, 0, UTF8String)
// 	AvpErrorReportingHost          = NewAVPAttributes("Error-Reporting-Host", 294, 0, DiamIdent)
// 	AvpEventTimestamp              = NewAVPAttributes("Event-Timestamp", 55, 0, Time)
// 	AvpExperimentalResult          = NewAVPAttributes("Experimental-Result", 297, 0, Grouped)
// 	AvpExperimentalResultCode      = NewAVPAttributes("Experimental-Result-Code", 298, 0, Unsigned32)
// 	AvpFailedAvp                   = NewAVPAttributes("Failed-AVP", 279, 0, Grouped)
// 	AvpFirmwareRevision            = NewAVPAttributes("Firmware-Revision", 267, 0, Unsigned32)
// 	AvpHostIPAddress               = NewAVPAttributes("Host-IP-Address", 257, 0, Address)
// 	AvpInbandSecurityID            = NewAVPAttributes("Inband-Security-Id", 299, 0, Unsigned32)
// 	AvpMultiRoundTimeOut           = NewAVPAttributes("Multi-Round-Time-Out", 272, 0, Unsigned32)
// 	AvpOriginHost                  = NewAVPAttributes("Origin-Host", 264, 0, DiamIdent)
// 	AvpOriginRealm                 = NewAVPAttributes("Origin-Realm", 296, 0, DiamIdent)
// 	AvpOriginStateID               = NewAVPAttributes("Origin-State-Id", 278, 0, Unsigned32)
// 	AvpProductName                 = NewAVPAttributes("Product-Name", 269, 0, UTF8String)
// 	AvpProxyHost                   = NewAVPAttributes("Proxy-Host", 280, 0, DiamIdent)
// 	AvpProxyInfo                   = NewAVPAttributes("Proxy-Info", 284, 0, Grouped)
// 	AvpProxyState                  = NewAVPAttributes("Proxy-State", 33, 0, OctetString)
// 	AvpRedirectHost                = NewAVPAttributes("Redirect-Host", 292, 0, DiamURI)
// 	AvpRedirectHostUsage           = NewAVPAttributes("Redirect-Host-Usage", 261, 0, Enumerated)
// 	AvpRedirectMaxCacheTime        = NewAVPAttributes("Redirect-Max-Cache-Time", 262, 0, Unsigned32)
// 	AvpResultCode                  = NewAVPAttributes("Result-Code", 268, 0, Unsigned32)
// 	AvpRouteRecord                 = NewAVPAttributes("Route-Record", 282, 0, DiamIdent)
// 	AvpSessionID                   = NewAVPAttributes("Session-Id", 263, 0, UTF8String)
// 	AvpSessionTimeout              = NewAVPAttributes("Session-Timeout", 27, 0, Unsigned32)
// 	AvpSessionBinding              = NewAVPAttributes("Session-Binding", 270, 0, Unsigned32)
// 	AvpSessionServerFailover       = NewAVPAttributes("Session-Server-Failover", 271, 0, Enumerated)
// 	AvpSubscriptionID              = NewAVPAttributes("Subscription-Id", 443, 0, Grouped)
// 	AvpSubscriptionIDData          = NewAVPAttributes("Subscription-Id-Data", 444, 0, UTF8String)
// 	AvpSubscriptionIDType          = NewAVPAttributes("Subscription-Id-Type", 450, 0, Enumerated)
// 	AvpSupportedVendorID           = NewAVPAttributes("Supported-Vendor-Id", 265, 0, Unsigned32)
// 	AvpTerminationCause            = NewAVPAttributes("Termination-Cause", 295, 0, Enumerated)
// 	AvpUserName                    = NewAVPAttributes("User-Name", 1, 0, UTF8String)
// 	AvpVendorID                    = NewAVPAttributes("Vendor-Id", 266, 0, Unsigned32)
// 	AvpVendorSpecificApplicationID = NewAVPAttributes("Vendor-Specific-Application-Id", 260, 0, Grouped)
// )

// AVP represents a Diameter Message AVP
type AVP struct {
	Code           uint32
	VendorSpecific bool
	Mandatory      bool
	Protected      bool
	VendorID       uint32
	Data           []byte
	Length         int
	PaddedLength   int
	//	DataType       AVPDataType
	//	Flags          byte
	//	Attribute      *AVPAttributes
	//	Typed          interface{}
}

// NewAVP is an AVP constructor
func NewAVP(code uint32, VendorID uint32, mandatory bool, protected bool, dataType AVPDataType, data []byte) *AVP { //, typedData interface{}) *AVP {
	avp := new(AVP)
	avp.Code = code
	avp.VendorID = VendorID
	if VendorID != 0 {
		avp.VendorSpecific = true
	} else {
		avp.VendorSpecific = false
	}
	avp.Mandatory = mandatory
	avp.Protected = protected
	avp.Data = data
	//avp.Typed = typedData
	//avp.Flags = 0x00
	// if avp.Mandatory {
	// 	avp.Flags |= avpMandatoryFlag
	// }
	// if avp.Protected {
	// 	avp.Flags |= avpProtectedFlag
	// }
	// if avp.VendorSpecific {
	// 	avp.Flags |= avpFlagVendorSpecific
	// }

	avp.Length = avpHeaderLength
	//if avp.Data != nil {
	buf := bytes.NewReader(avp.Data)
	avp.readRaw(buf)
	//} else if avp.Typed != nil {
	// rawType := reflect.TypeOf(avp.Typed)
	// switch avp.Attribute.dataType {
	// case Unsigned32, Enumerated:
	// 	avp.Raw = make([]byte, 4)
	// 	binary.BigEndian.PutUint32(avp.Raw, uint32(avp.Typed.(uint32)))
	// case DiamIdent, UTF8String:
	// 	avp.Raw = []byte(avp.Typed.(string))
	// case Address:
	// 	address, ok := avp.Typed.(net.IP)
	// 	if !ok {
	// 		address = net.ParseIP(avp.Typed.(string))
	// 	}
	// 	buf := new(bytes.Buffer)
	// 	addrType := uint16(addrIPv6)
	// 	if address.To4() != nil {
	// 		address = address.To4()
	// 		addrType = uint16(addrIPv4)
	// 	}
	// 	appendUint16(buf, addrType)
	// 	appendByteArray(buf, []byte(address))
	// 	avp.Raw = buf.Bytes()
	// case Grouped:
	// 	avps, ok := avp.Typed.([]*AVP)
	// 	if !ok {
	// 		// XXX: this is debugging and should be removed
	// 		fmt.Println("kind:", rawType.Kind())
	// 	}
	// 	buf := new(bytes.Buffer)
	// 	for i := 0; i < len(avps); i++ {
	// 		appendByteArray(buf, avps[i].Encode())
	// 	}
	// 	avp.Raw = buf.Bytes()
	// default:
	// 	// XXX: this is debugging and should be removed
	// 	fmt.Println("kind:", rawType.Kind())
	// }
	//}
	avp.Length += len(data)
	avp.updatePaddedLength()
	return avp
}

// // SetMandatoryFlag sets the mandatory flag value to on (true) or off (false)
// func (avp *AVP) SetMandatoryFlag(mandatory bool) {
// 	avp.Mandatory = mandatory
// 	if avp.Mandatory {
// 		avp.Flags |= avpMandatoryFlag
// 	} else if (avp.Flags & avpMandatoryFlag) == avpMandatoryFlag {
// 		avp.Flags ^= avpMandatoryFlag
// 	}
// }
//
// // SetProtectedFlag set the protected flag value to on (true) or off (false)
// func (avp *AVP) SetProtectedFlag(protected bool) {
// 	avp.Protected = protected
// 	if avp.Protected {
// 		avp.Flags |= avpProtectedFlag
// 	} else if (avp.Flags & avpProtectedFlag) == avpProtectedFlag {
// 		avp.Flags ^= avpProtectedFlag
// 	}
// }

func appendUint16(avp *bytes.Buffer, dataUint16 uint16) {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, dataUint16)
	err := binary.Write(avp, binary.LittleEndian, data)
	if err != nil {
		// XXX: errors should be propagated
		fmt.Println("binary.Write failed:", err)
	}
}

func appendUint32(avp *bytes.Buffer, dataUint32 uint32) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, dataUint32)
	err := binary.Write(avp, binary.LittleEndian, data)
	if err != nil {
		// XXX: errors should be propagated
		fmt.Println("binary.Write failed:", err)
	}
}

func appendByteArray(avp *bytes.Buffer, dataBytes []byte) {
	err := binary.Write(avp, binary.LittleEndian, dataBytes)
	if err != nil {
		// XXX: errors should be propagated
		fmt.Println("binary.Write failed:", err)
	}
}

func byteToUint32(data []byte) (ret uint32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

// Encode produces an octet stream in network byte order from this AVP
func (avp *AVP) Encode() []byte {
	buf := new(bytes.Buffer)
	padded := make([]byte, (avp.PaddedLength - avp.Length))
	appendUint32(buf, avp.Code)
	flags := 0

	if avp.VendorSpecific {
		flags = 0x80
	}
	if avp.Mandatory {
		flags |= 0x40
	}
	if avp.Protected {
		flags |= 0x20
	}

	appendUint32(buf, ((uint32(flags) << 24) | (uint32(avp.Length) & 0x00ffffff)))
	appendByteArray(buf, avp.Data)
	appendByteArray(buf, padded)

	return buf.Bytes()
}

// func (avp *AVP) setMandatoryFlag(v bool) {
// 	avp.Mandatory = v
//
// 	if v {
// 		avp.Flags |= avpMandatoryFlag
// 	} else {
// 		avp.Flags = avp.Flags &^ avpMandatoryFlag
// 	}
// }

func (avp *AVP) updatePaddedLength() {
	plen := (avp.Length) & 0x00000003
	if plen > 0 {
		avp.PaddedLength = avp.Length + (4 - plen)
	} else {
		avp.PaddedLength = avp.Length
	}
}

// Equal compares the current AVP to another AVP to determine if they are byte-wise
// identical (that is, if they would map identically as a byte stream using Encode)
func (avp *AVP) Equal(a *AVP) bool {
	// XXX: one should be able to accomplish this with a straight memory content comparison
	if a == nil {
		return false
	}

	if avp.Code != a.Code || avp.VendorSpecific != a.VendorSpecific || avp.Mandatory != a.Mandatory || avp.VendorID != a.VendorID || avp.Length != a.Length || avp.PaddedLength != a.PaddedLength {
		return false
	}

	// if avp.Attribute.code != a.Attribute.code {
	// 	return false
	// }

	// XXX: there is a bug in the Encode procedure that needs to be fixed before this can work
	//    if bytes.Compare(s.Raw, a.Raw) != 0 {
	//        return false
	//    }

	return true
}

func (avp *AVP) readRaw(buf io.Reader) error {
	// dataLength := avp.Length - avpHeaderLength
	// if avp.VendorSpecific == true {
	// 	dataLength -= 4
	// }

	// switch avp.Attribute.dataType {
	// case Address:
	// 	var addrType uint16
	// 	err := binary.Read(buf, binary.BigEndian, &addrType)
	// 	dataLength -= 2
	// 	if err != nil {
	// 		return fmt.Errorf("stream read failure: %s", err)
	// 	}
	// 	avp.Raw = make([]byte, dataLength)
	// 	_, err = buf.Read(avp.Raw)
	// 	if err != nil {
	// 		// XXX: errors should be propagated
	// 		return fmt.Errorf("stream read failure: %s", err)
	// 	}
	// 	avp.Typed = net.IP(avp.Raw)
	// case DiamIdent, UTF8String:
	// 	avp.Raw = make([]byte, dataLength)
	// 	_, err := buf.Read(avp.Raw)
	// 	if err != nil {
	// 		return fmt.Errorf("stream read failure: %s", err)
	// 	}
	// 	avp.Typed = string(avp.Raw)
	// case Unsigned32, Enumerated:
	// 	avp.Raw = make([]byte, 4)
	// 	_, err := buf.Read(avp.Raw)
	// 	if err != nil {
	// 		return fmt.Errorf("stream read failure: %s", err)
	// 	}
	// 	avp.Typed = byteToUint32(avp.Raw)
	// case Grouped:
	// 	avp.Raw = make([]byte, dataLength)
	// 	_, err := buf.Read(avp.Raw)
	// 	if err != nil {
	// 		return fmt.Errorf("stream read failure: %s", err)
	// 	}
	// 	avp.Typed = []*AVP{}
	// 	sliceStart := 0
	// 	for dataLength > avpHeaderLength {
	// 		avpValue, err := DecodeAVP(avp.Raw[sliceStart:], make(map[uint32]AVPType))
	// 		avp.Typed = append(avp.Typed.([]*AVP), avpValue)
	// 		sliceStart += avpValue.Length
	// 		dataLength -= avpValue.Length
	// 	}
	// default:
	// 	return fmt.Errorf("AVP type (%d) not understood", avp.Attribute.dataType)
	// }

	return nil
}

// DecodeAVP accepts a byte stream in network byte order and produces an AVP
// object from it.
func DecodeAVP(input []byte) (*AVP, error) {
	avp := new(AVP)
	buf := bytes.NewReader(input)
	var code uint32
	err := binary.Read(buf, binary.BigEndian, &code)
	if err != nil {
		return nil, fmt.Errorf("stream read failure: %s", err)
	}

	avp.Code = code

	var flagsAndLength uint32
	err = binary.Read(buf, binary.BigEndian, &flagsAndLength)
	if err != nil {
		return nil, fmt.Errorf("stream read failure: %s", err)
	}
	flags := byte((flagsAndLength & 0xFF000000) >> 24)
	avp.Length = int(flagsAndLength & 0x00FFFFFF)
	avp.Mandatory = bool((avpMandatoryFlag & flags) == avpMandatoryFlag)
	avp.Protected = bool((avpProtectedFlag & flags) == avpProtectedFlag)
	avp.VendorSpecific = bool((avpFlagVendorSpecific & flags) == avpFlagVendorSpecific)

	//	dataLength := avp.Length - avpHeaderLength
	if avp.VendorSpecific == true {
		err = binary.Read(buf, binary.BigEndian, &avp.VendorID)
		if err != nil {
			return nil, fmt.Errorf("stream read failure: %s", err)
		}
	}

	err = avp.readRaw(buf)

	if err != nil {
		return nil, err
	}

	avp.updatePaddedLength()

	return avp, nil
}
