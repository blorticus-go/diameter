package diameter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	avpProtectedFlag                 = 0x20
	avpMandatoryFlag                 = 0x40
	avpFlagVendorSpecific            = 0x80
	nonVendorSpecificAvpHeaderLength = 8
	vendorSpecificAvpHeaderLength    = 12
)

// these are the leading type qualifier values in an AVP value of Address type
const (
	addrIPv4 = 1
	addrIPv6 = 2
)

// AVPDataType is an enumeration of Diameter AVP types
type AVPDataType int

const (
	// Unsigned32 indicates AVP type for unsigned 32-bit integer
	Unsigned32 AVPDataType = 1 + iota
	// Unsigned64 indicates AVP type for unsigned 64-bit integer
	Unsigned64
	// Integer32 indicates AVP type for signed 32-bit integer
	Integer32
	// Integer64 indicates AVP type for signed 64-bit integer
	Integer64
	// Float32 indicates AVP type for signed 32-bit floating point
	Float32
	// Float64 indicates AVP type for signed 64-bit floating point
	Float64
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
	// IPFilterRule indicates AVP type for IP Filter Rule
	IPFilterRule
	// TypeOrAvpUnknown is used when a query is made for an unknown AVP or the dictionary
	// contains an unknown type
	TypeOrAvpUnknown
)

var diameterBaseTime time.Time = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)

// AVPExtendedAttributes includes extended AVP attributes that can be
// provided by, for example, a dictionary.  It includes a human-friendly name
// and a typed value (e.g., a uint32 for AVPs of Unsigned32 type)
type AVPExtendedAttributes struct {
	Name       string
	DataType   AVPDataType
	TypedValue interface{}
}

// AVP represents a Diameter Message AVP
type AVP struct {
	Code               uint32
	VendorSpecific     bool
	Mandatory          bool
	Protected          bool
	VendorID           uint32
	Data               []byte
	Length             int
	PaddedLength       int
	ExtendedAttributes *AVPExtendedAttributes
}

// NewAVP is an AVP constructor
func NewAVP(code uint32, VendorID uint32, mandatory bool, data []byte) *AVP {
	avp := new(AVP)
	avp.Code = code
	avp.VendorID = VendorID
	if VendorID != 0 {
		avp.Length = vendorSpecificAvpHeaderLength
		avp.VendorSpecific = true
	} else {
		avp.Length = nonVendorSpecificAvpHeaderLength
		avp.VendorSpecific = false
	}
	avp.Mandatory = mandatory
	avp.Protected = false
	avp.Data = data

	avp.Length += len(data)
	avp.updatePaddedLength()

	avp.ExtendedAttributes = nil

	return avp
}

// NewTypedAVPErrorable is an AVP constructor provided typed data rather than the raw data.  Returns an
// error if the value is not convertible from the avpType.  The ExtendedAttributes will be set, but the
// Name will be the empty string
func NewTypedAVPErrorable(code uint32, vendorID uint32, mandatory bool, avpType AVPDataType, value interface{}) (*AVP, error) {
	var data []byte

	switch avpType {
	case Unsigned32:
		v, isUnsigned32 := value.(uint32)

		if !isUnsigned32 {
			return nil, fmt.Errorf("AVP type should be Unsigned32, but is not")
		}

		data = make([]byte, 4)
		binary.BigEndian.PutUint32(data, v)

	case Unsigned64:
		v, isUnsigned64 := value.(uint64)

		if !isUnsigned64 {
			return nil, fmt.Errorf("AVP type should be Unsigned64, but is not")
		}

		data = make([]byte, 8)
		binary.BigEndian.PutUint64(data, v)

	case Integer32:
		v, isInt32 := value.(int32)

		if !isInt32 {
			return nil, fmt.Errorf("AVP type should be int32, but is not")
		}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)

		data = buf.Bytes()

	case Integer64:
		v, isInt64 := value.(int64)

		if !isInt64 {
			return nil, fmt.Errorf("AVP type should be int64, but is not")
		}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)

		data = buf.Bytes()

	case Float32:
		v, isFloat32 := value.(float32)

		if !isFloat32 {
			return nil, fmt.Errorf("AVP type should be float32, but is not")
		}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)

		data = buf.Bytes()

	case Float64:
		v, isFloat64 := value.(float64)

		if !isFloat64 {
			return nil, fmt.Errorf("AVP type should be float64, but is not")
		}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)

		data = buf.Bytes()

	case UTF8String:
		v, isString := value.(string)

		if isString {
			data = []byte(v)
		} else {
			v, isByteSlice := value.([]byte)

			if !isByteSlice {
				return nil, fmt.Errorf("AVP type should be string or []byte, but is neither")
			}

			data = v
		}

	case OctetString:
		v, isByteSlice := value.([]byte)

		if !isByteSlice {
			return nil, fmt.Errorf("AVP type should []byte, but is not")
		}

		data = v

	case Enumerated:
		v, isInt32 := value.(int32)

		if !isInt32 {
			return nil, fmt.Errorf("AVP type should be int32, but is not")
		}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)

		data = buf.Bytes()

	case Time:
		switch value.(type) {
		case []byte:
			v := value.([]byte)

			if len(v) != 4 {
				return nil, fmt.Errorf("AVP byte length must be 4, but is (%d)", len(v))
			}

			data = v

		case uint32:
			data = make([]byte, 4)
			binary.BigEndian.PutUint32(data, value.(uint32))

		case time.Time:
			v := value.(time.Time)
			return NewTypedAVPErrorable(code, vendorID, mandatory, avpType, &v)

		case *time.Time:
			durationSinceDiameterBaseTime := value.(*time.Time).Sub(diameterBaseTime) / time.Second

			if durationSinceDiameterBaseTime < 0 {
				return nil, fmt.Errorf("Provided Time is earlier than the Diameter Epoch (Jan 01, 1900 UTC)")
			}

			if durationSinceDiameterBaseTime > 4294967295 {
				return nil, fmt.Errorf("Provided Time is later than Diameter time can represent")
			}

			data = make([]byte, 4)
			binary.BigEndian.PutUint32(data, uint32(durationSinceDiameterBaseTime))

		default:
			return nil, fmt.Errorf("AVP of Time type must be uint32, time.Time or *time.Time")
		}

	case Address:
		v, isIP := value.(net.IP)

		if !isIP {
			w, isIPAddr := value.(net.IPAddr)

			if !isIPAddr {
				w, isIPAddrPtr := value.(*net.IPAddr)

				if !isIPAddrPtr {
					return nil, fmt.Errorf("AVP type should be net.IP, net.IPAddr or *net.IPAddr, but is none of those")
				}

				v = w.IP
			} else {
				v = w.IP
			}
		}

		if v.To4() == nil {
			data = make([]byte, 18)
			data[0] = 0x00
			data[1] = 0x02
			copy(data[2:], v.To16())
		} else {
			data = make([]byte, 6)
			data[0] = 0x00
			data[1] = 0x01
			copy(data[2:], v.To4())
		}

	case DiamIdent:
		v, isString := value.(string)

		if !isString {
			return nil, fmt.Errorf("DiamIdent AVP type should string, but is not")
		}

		data = []byte(v)

	case DiamURI:
		v, isByteSlice := value.(string)

		if !isByteSlice {
			return nil, fmt.Errorf("DiamURI AVP type should string, but is not")
		}

		data = []byte(v)

	case Grouped:
		v, isAvpSlice := value.([]*AVP)

		if !isAvpSlice {
			return nil, fmt.Errorf("AVP type should []*AVP, but is not")
		}

		avpDataLen := 0
		for _, avp := range v {
			avpDataLen += avp.PaddedLength
		}

		data = make([]byte, 0, avpDataLen)

		for _, avp := range v {
			data = append(data, avp.Encode()...)
		}

	case IPFilterRule:
		v, isString := value.(string)

		if isString {
			data = []byte(v)
		} else {
			v, isByteSlice := value.([]byte)

			if !isByteSlice {
				return nil, fmt.Errorf("AVP type should be string or []byte, but is neither")
			}

			data = v
		}

	default:
		return nil, fmt.Errorf("type not valid for an AVP")
	}

	isVendorSpecific := false
	avpLength := nonVendorSpecificAvpHeaderLength
	if vendorID != 0 {
		isVendorSpecific = true
		avpLength = vendorSpecificAvpHeaderLength
	}

	avpLength += len(data)

	paddedLength := avpLength
	carry := avpLength % 4
	if carry > 0 {
		paddedLength += (4 - carry)
	}

	return &AVP{
		Code:           code,
		VendorID:       vendorID,
		VendorSpecific: isVendorSpecific,
		Mandatory:      mandatory,
		Protected:      false,
		Data:           data,
		Length:         avpLength,
		PaddedLength:   paddedLength,
		ExtendedAttributes: &AVPExtendedAttributes{
			DataType:   avpType,
			TypedValue: value,
			Name:       "",
		},
	}, nil
}

// NewTypedAVP is the same as NewTypedAVPErrorable, except that it raises panic() on an error
func NewTypedAVP(code uint32, vendorID uint32, mandatory bool, avpType AVPDataType, value interface{}) *AVP {
	avp, err := NewTypedAVPErrorable(code, vendorID, mandatory, avpType, value)

	if err != nil {
		panic(err)
	}

	return avp
}

// ConvertAVPDataToTypedData attempts to convert the provided AVP data into a typed value,
// according to the data type provided.
func ConvertAVPDataToTypedData(avpData []byte, dataType AVPDataType) (interface{}, error) {
	switch dataType {
	case Unsigned32:
		if len(avpData) != 4 {
			return nil, fmt.Errorf("Unsigned32 type requires exactly four bytes")
		}

		return binary.BigEndian.Uint32(avpData), nil

	case Unsigned64:
		if len(avpData) != 8 {
			return nil, fmt.Errorf("Unsigned64 type requires exactly eight bytes")
		}

		return binary.BigEndian.Uint64(avpData), nil

	case Integer32:
		if len(avpData) != 4 {
			return nil, fmt.Errorf("Integer32 type requires exactly four bytes")
		}

		return int32(binary.BigEndian.Uint32(avpData)), nil

	case Integer64:
		if len(avpData) != 8 {
			return nil, fmt.Errorf("Integer64 type requires exactly eight bytes")
		}

		return int64(binary.BigEndian.Uint64(avpData)), nil

	case Float32:
		if len(avpData) != 4 {
			return nil, fmt.Errorf("Float32 type requires exactly four bytes")
		}

		return float32(binary.BigEndian.Uint32(avpData)), nil

	case Float64:
		if len(avpData) != 8 {
			return nil, fmt.Errorf("Float64 type requires exactly eight bytes")
		}

		return float64(binary.BigEndian.Uint64(avpData)), nil

	case UTF8String:
		return string(avpData), nil

	case OctetString:
		return avpData[:], nil

	case Enumerated:
		if len(avpData) != 4 {
			return nil, fmt.Errorf("Enumerated type requires exactly four bytes")
		}

		return int32(binary.BigEndian.Uint32(avpData)), nil

	case Time:
		if len(avpData) != 4 {
			return nil, fmt.Errorf("Time type requires exactly four bytes")
		}

		return binary.BigEndian.Uint32(avpData), nil

	case Address:
		switch len(avpData) {
		case 6:
			if binary.BigEndian.Uint16(avpData[:2]) != 1 {
				return nil, fmt.Errorf("Address Type must be for IPv4 or IPv6 address only")
			}
			return net.IPv4(avpData[2], avpData[3], avpData[4], avpData[5]), nil

		case 10:
			if binary.BigEndian.Uint16(avpData[:2]) != 2 {
				return nil, fmt.Errorf("Address Type must be for IPv4 or IPv6 address only")
			}
			ipAddr := net.IP(avpData[2:])
			return &ipAddr, nil

		default:
			return nil, fmt.Errorf("Address type requires exactly 6 bytes or 10 bytes")
		}

	case DiamIdent:
		return string(avpData), nil

	case Grouped:
		groupedBytes := avpData
		avpsInGroup := make([]*AVP, 10)

		for len(groupedBytes) > 0 {
			nextAvp, err := DecodeAVP(groupedBytes)
			if err != nil {
				return nil, fmt.Errorf("unable to decode AVP inside group: %s", err.Error())
			}
			avpsInGroup = append(avpsInGroup, nextAvp)
			groupedBytes = groupedBytes[nextAvp.PaddedLength+1:]
		}

		return avpsInGroup, nil

	case IPFilterRule:
		return avpData[:], nil

	default:
		return nil, fmt.Errorf("type not valid for an AVP")
	}
}

// MakeProtected sets avp.Protected to true and returns the AVP reference.  It is so rare for
// this flag to be set, this provides a convenient method to set the value inline after
// AVP creation
func (avp *AVP) MakeProtected() *AVP {
	avp.Protected = true
	return avp
}

// ConvertDataToTypedData overrides any internally stored typed data representation for
// the AVP and attempts to convert the raw data into the named type.
func (avp *AVP) ConvertDataToTypedData(dataType AVPDataType) (interface{}, error) {
	return ConvertAVPDataToTypedData(avp.Data, dataType)
}

// func appendUint16(avp *bytes.Buffer, dataUint16 uint16) {
// 	data := make([]byte, 2)
// 	binary.BigEndian.PutUint16(data, dataUint16)
// 	err := binary.Write(avp, binary.LittleEndian, data)
// 	if err != nil {
// 		// XXX: errors should be propagated
// 		fmt.Println("binary.Write failed:", err)
// 	}
// }

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

func (avp *AVP) updateTypedValueFromData(d *Dictionary) error {
	switch avp.ExtendedAttributes.DataType {
	case Address:
		if len(avp.Data) < 2 {
			return errors.New("AVP attribute type is Address, but data length only 2 bytes")
		}

		addrType := binary.BigEndian.Uint32(avp.Data[0:2])
		if addrType == 1 {
			if len(avp.Data) != 6 {
				return errors.New("AVP attribute type is Address, type is IPv4, but data length is not 6")
			}
		} else if addrType == 2 {
			if len(avp.Data) != 18 {
				return errors.New("AVP attribute type is Address, type is IPv6, but data length is not 18")
			}
		} else {
			return errors.New("AVP attribute type is Address and only IPv4 or IPv6 families are supported")
		}

		avp.ExtendedAttributes.TypedValue = net.IP(avp.Data[2:])

	case Unsigned32, Enumerated:
		if len(avp.Data) != 4 {
			return errors.New("AVP attribute type is 32-bit unsigned integer, but data length is not 4 bytes")
		}

		avp.ExtendedAttributes.TypedValue = binary.BigEndian.Uint32(avp.Data)

	case DiamIdent, UTF8String:
		avp.ExtendedAttributes.TypedValue = string(avp.Data)

	case Grouped:
		tv := []*AVP{}

		dataSliceOffset := 0

		for dataSliceOffset < avp.PaddedLength {
			nextAVP, naArr := DecodeAVP(avp.Data[dataSliceOffset:])
			if naArr != nil {
				return fmt.Errorf("Failed to extract Grouped AVP member: %s", naArr.Error())
			}

			if d != nil {
				//	nextAVP.AddExtendedAttributesFromDictionary(d)
			}

			tv = append(tv, nextAVP)
			dataSliceOffset += nextAVP.PaddedLength - 1
		}

		avp.ExtendedAttributes.TypedValue = tv

	default:
		avp.ExtendedAttributes.TypedValue = avp.Data
	}

	return nil
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

	if avp.VendorSpecific {
		appendUint32(buf, avp.VendorID)
	}

	appendByteArray(buf, avp.Data)
	appendByteArray(buf, padded)

	return buf.Bytes()
}

func (avp *AVP) updatePaddedLength() {
	plen := (avp.Length) & 0x00000003
	if plen > 0 {
		avp.PaddedLength = avp.Length + (4 - plen)
	} else {
		avp.PaddedLength = avp.Length
	}
}

// Clone makes a copy of this AVP and returns it.  No effort is made to
// make the copy thread-safe.
func (avp *AVP) Clone() *AVP {
	clone := *avp
	clone.Data = make([]byte, len(avp.Data))
	copy(clone.Data, avp.Data)
	return &clone
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

	if len(avp.Data) != len(a.Data) {
		return false
	}

	for i, leftAvpByteValue := range avp.Data {
		if leftAvpByteValue != a.Data[i] {
			return false
		}
	}

	return true
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

	if avp.Length > len(input) {
		return nil, fmt.Errorf("length field in AVP header greater than encoded length")
	}

	//	dataLength := avp.Length - avpHeaderLength
	headerLength := nonVendorSpecificAvpHeaderLength

	if avp.VendorSpecific == true {
		err = binary.Read(buf, binary.BigEndian, &avp.VendorID)
		if err != nil {
			return nil, fmt.Errorf("stream read failure: %s", err)
		}
		headerLength = vendorSpecificAvpHeaderLength
	}

	//err = avp.readRaw(buf)
	avp.Data = make([]byte, avp.Length-headerLength)

	err = binary.Read(buf, binary.BigEndian, avp.Data)

	if err != nil {
		return nil, err
	}

	avp.updatePaddedLength()

	return avp, nil
}
