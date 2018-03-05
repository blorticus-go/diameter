package diameter

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
}

// NewAVP is an AVP constructor
func NewAVP(code uint32, VendorID uint32, mandatory bool, protected bool, data []byte) *AVP {
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

	avp.Length = avpHeaderLength

	avp.Length += len(data)
	avp.updatePaddedLength()
	return avp
}

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
	headerLength := avpHeaderLength

	if avp.VendorSpecific == true {
		err = binary.Read(buf, binary.BigEndian, &avp.VendorID)
		if err != nil {
			return nil, fmt.Errorf("stream read failure: %s", err)
		}
		headerLength += 4
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
