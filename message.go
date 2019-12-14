package diameter

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Uint24 is a documentation reference type.  There is no enforcement of boundaries;
// it is simply a visual reminder of the type
type Uint24 uint32

// Possible flag values for a Diameter message
const (
	MsgFlagRequest             = 0x80
	MsgFlagProxiable           = 0x40
	MsgFlagError               = 0x20
	MsgFlagPotentialRetransmit = 0x10
	MsgHeaderSize              = Uint24(20)
)

// Message represents a single Diameter message
type Message struct {
	Version    uint8
	Length     Uint24
	Flags      uint8
	Code       Uint24
	AppID      uint32
	HopByHopID uint32
	EndToEndID uint32
	Avps       []*AVP
}

// FindFirstAVPByCode returns the first instance of the identified AVP associated
// with the current Message, or nil if the Message has no instances of the AVP
func (m *Message) FindFirstAVPByCode(code Uint24) *AVP {
	for _, avp := range m.Avps {
		if avp.Code == uint32(code) {
			return avp
		}
	}

	return nil
}

// IsRequest returns true if the message is a Diameter Request message (that
// is, the request flag in the Diameter message header is set)
func (m *Message) IsRequest() bool {
	return (m.Flags & MsgFlagRequest) != 0
}

// IsProxiable returns true if the proxiable flag in the Diameter message header is set
func (m *Message) IsProxiable() bool {
	return (m.Flags & MsgFlagProxiable) != 0
}

// IsError returns true if the message is a Diameter erro9r message (that
// is, the error flag in the Diameter message header is set)
func (m *Message) IsError() bool {
	return (m.Flags & MsgFlagError) != 0
}

// IsPotentiallyRetransmitted returns true if the potentially retransmit
// flag in the Diameter message header is set
func (m *Message) IsPotentiallyRetransmitted() bool {
	return (m.Flags & MsgFlagPotentialRetransmit) != 0
}

// Encode transforms the current message into an octet stream appropriate
// for network transmission
func (m *Message) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, uint32(m.Version)<<24|uint32(m.Length)&0x00ffffff)
	binary.Write(buf, binary.BigEndian, uint32(m.Flags)<<24|uint32(m.Code)&0x00ffffff)
	binary.Write(buf, binary.BigEndian, m.AppID)
	binary.Write(buf, binary.BigEndian, m.HopByHopID)
	binary.Write(buf, binary.BigEndian, m.EndToEndID)
	for _, avp := range m.Avps {
		buf.Write(avp.Encode())
	}
	return buf.Bytes()
}

// DecodeMessage accepts an octet stream and attempts to interpret it as a Diameter
// message.  The stream must at least a single Diameter
// message.  To decode incoming streams, use a MessageStreamReader.  If the input
// stream is at least one Diameter message, or an error occurs in the reading of
// the stream or creation of the message, return nil and an error; otherwise
// return a Message object and nil for the error.
func DecodeMessage(input []byte) (*Message, error) {
	m := new(Message)
	buf := bytes.NewReader(input)
	var flagsAndLength uint32
	err := binary.Read(buf, binary.BigEndian, &flagsAndLength)
	if err != nil {
		return nil, err
	}

	m.Version = byte((flagsAndLength & 0xFF000000) >> 24)
	m.Length = Uint24(flagsAndLength & 0x00FFFFFF)

	if Uint24(len(input)) < m.Length {
		return nil, errors.New("Header length does not match stream length")
	}

	err = binary.Read(buf, binary.BigEndian, &flagsAndLength)
	if err != nil {
		return nil, err
	}

	m.Flags = byte((flagsAndLength & 0xFF000000) >> 24)
	m.Code = Uint24(flagsAndLength & 0x00FFFFFF)

	err = binary.Read(buf, binary.BigEndian, &m.AppID)
	if err != nil {
		return nil, err
	}

	err = binary.Read(buf, binary.BigEndian, &m.HopByHopID)
	if err != nil {
		return nil, err
	}

	err = binary.Read(buf, binary.BigEndian, &m.EndToEndID)
	if err != nil {
		return nil, err
	}

	m.Avps = make([]*AVP, 0)
	b := input[MsgHeaderSize:int(m.Length)]
	for len(b) > 0 {
		var avp *AVP
		avp, err = DecodeAVP(b)

		if err != nil {
			return nil, err
		}

		b = b[avp.PaddedLength:]
		m.Avps = append(m.Avps, avp)
	}

	if err != nil {
		return nil, err
	}
	return m, err
}

// NewMessage creates a new diameter.Message instance.  'mandatoryAvps' will all
// have their Mandatory flag set to true.  The Mandatory flag for 'additionalAvps'
// will be left untouched.
func NewMessage(flags uint8, code Uint24, appID uint32, hopByHopID uint32, endToEndID uint32, mandatoryAvps []*AVP, additionalAvps []*AVP) (m *Message) {
	m = new(Message)

	m.Version = 1
	m.Flags = flags & 0xf0
	m.Code = code & 0x00ffffff
	m.AppID = appID
	m.HopByHopID = hopByHopID
	m.EndToEndID = endToEndID
	m.Avps = make([]*AVP, len(mandatoryAvps)+len(additionalAvps))

	m.Length = MsgHeaderSize
	for i := 0; i < len(mandatoryAvps); i++ {
		m.Length += Uint24(mandatoryAvps[i].PaddedLength)
		m.Avps[i] = mandatoryAvps[i]
		m.Avps[i].Mandatory = true
	}

	t := len(mandatoryAvps)

	for i := 0; i < len(additionalAvps); i++ {
		m.Length += Uint24(additionalAvps[i].PaddedLength)
		m.Avps[t+i] = additionalAvps[i]
	}

	return m
}

// Equal compares the current Message object to a different message object.  If
// they have equivalent values for all fields and AVPs, return true; otherwise
// return false.  AVPs are compared exactly in order.
func (m *Message) Equal(c *Message) bool {
	// XXX: This can almost certainly be made into just a straight memory
	// value comparison between the two objects.
	if m == nil {
		return false
	}

	if m.Version != c.Version || m.Flags != c.Flags || m.Code != c.Code || m.AppID != c.AppID || m.HopByHopID != c.HopByHopID || m.EndToEndID != c.EndToEndID {
		return false
	}

	if len(m.Avps) != len(c.Avps) {
		return false
	}

	for i := 0; i < len(m.Avps); i++ {
		if !m.Avps[i].Equal(c.Avps[i]) {
			return false
		}
	}

	return true
}

const (
	streamReaderBaseBufferSizeInBytes int = 16384
)

// MessageStreamReader simplifies the reading of an octet stream which must be
// converted to one or more diameter.Message objects.  Generally, a new
// MessageStreamReader is created, then ReceiveBytes() is repeatedly called on
// an input stream (which must be in network byte order) as bytes arrive.
// This method will return diameter.Message objects as they can be extracted, and
// store any bytes that are left over after message conversion
type MessageStreamReader struct {
	incomingBuffer []byte
}

// NewMessageStreamReader creates a new MessageStreamReader object
func NewMessageStreamReader() *MessageStreamReader {
	return &MessageStreamReader{
		incomingBuffer: make([]byte, 0, streamReaderBaseBufferSizeInBytes),
	}
}

// ReceiveBytes returns one or more diameter.Message objects read from the incoming
// byte stream.  Return nil if no Message is yet found.  Return error on malformed
// byte stream.  If an error is returned, subsequent calls are no longer reliable.
func (reader *MessageStreamReader) ReceiveBytes(incoming []byte) ([]*Message, error) {
	reader.incomingBuffer = append(reader.incomingBuffer, incoming...)
	incomingBytesLeftToProcess := reader.incomingBuffer

	setOfExtractedMessages := make([]*Message, 0, 8)

	var nextMessageInStream *Message
	var err error
	for {
		nextMessageInStream, incomingBytesLeftToProcess, err = reader.extractNextMessageIfThereIsOne(incomingBytesLeftToProcess)

		if err != nil {
			return nil, err
		} else if nextMessageInStream != nil {
			setOfExtractedMessages = append(setOfExtractedMessages, nextMessageInStream)
		} else {
			if len(incomingBytesLeftToProcess) != len(reader.incomingBuffer) {
				if len(incomingBytesLeftToProcess) < streamReaderBaseBufferSizeInBytes {
					reader.incomingBuffer = make([]byte, 0, streamReaderBaseBufferSizeInBytes)
				} else {
					reader.incomingBuffer = make([]byte, 0, len(incomingBytesLeftToProcess)+streamReaderBaseBufferSizeInBytes)
				}
				reader.incomingBuffer = append(reader.incomingBuffer, incomingBytesLeftToProcess...)
			}

			return setOfExtractedMessages, nil
		}
	}
}

// Read a stream buffer and attempt to extract a Message, if there are enough
// bytes in the stream.  If not, return (nil, incoming, nil).  If the stream is malformed for
// a message, return (nil, incoming, error). If there is at least enough bytes for a message
// and the stream is well-formed, return (m, leftOverBytes, nil), where m is a Message and
// remainder is a slice of incoming, starting one byte after the extracted message.
func (reader MessageStreamReader) extractNextMessageIfThereIsOne(incoming []byte) (*Message, []byte, error) {
	if len(incoming) == 0 {
		return nil, incoming, nil
	}

	buf := bytes.NewReader(incoming)

	// 20 is the diameter header length
	if len(incoming) < 20 {
		var version uint8
		err := binary.Read(buf, binary.BigEndian, &version)

		if err != nil {
			return nil, incoming, err
		} else if version != 1 {
			return nil, incoming, errors.New("Unknown Diameter version")
		} else {
			return nil, incoming, nil
		}
	} else {
		var flagsAndLength uint32
		err := binary.Read(buf, binary.BigEndian, &flagsAndLength)

		if err != nil {
			return nil, incoming, err
		}

		version := byte((flagsAndLength & 0xFF000000) >> 24)
		length := Uint24(flagsAndLength & 0x00FFFFFF)

		if version != 1 {
			return nil, incoming, errors.New("Invalid Diameter message version")
		}

		if len(incoming) < int(length) {
			return nil, incoming, nil
		}

		m, err := DecodeMessage(incoming)

		if err != nil {
			return nil, incoming, err
		}

		return m, incoming[m.Length:], nil
	}
}
