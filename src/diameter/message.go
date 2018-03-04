package diameter

import (
	"bytes"
	"container/list"
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

// const (
// 	CodeAARequest                          = 265
// 	CodeAAR                                = 265
// 	CodeAAAnswer                           = 265
// 	CodeAAA                                = 265
// 	CodeDiameterEAPRequest                 = 268
// 	CodeDER                                = 268
// 	CodeDiameterEAPAnswer                  = 268
// 	CodeDEA                                = 268
// 	CodeAbortSessionRequest                = 274
// 	CodeASR                                = 274
// 	CodeAbortSessionAnswer                 = 274
// 	CodeASA                                = 274
// 	CodeAccountingRequest                  = 271
// 	CodeACR                                = 271
// 	CodeAccountingAnswer                   = 271
// 	CodeACA                                = 271
// 	CodeCreditControlRequest               = 272
// 	CodeCCR                                = 272
// 	CodeCreditControlAnswer                = 272
// 	CodeCCA                                = 272
// 	CodeCapabilitiesExchangeRequest        = 257
// 	CodeCER                                = 257
// 	CodeCapabilitiesExchangeAnswer         = 257
// 	CodeCEA                                = 257
// 	CodeDeviceWatchdogRequest              = 280
// 	CodeDWR                                = 280
// 	CodeDeviceWatchdogAnswer               = 280
// 	CodeDWA                                = 280
// 	CodeDisconnectPeerRequest              = 282
// 	CodeDPR                                = 282
// 	CodeDisconnectPeerAnswer               = 282
// 	CodeDPA                                = 282
// 	CodeReAuthRequest                      = 258
// 	CodeRAR                                = 258
// 	CodeReAuthAnswer                       = 258
// 	CodeRAA                                = 258
// 	CodeSessionTerminationRequest          = 275
// 	CodeSTR                                = 275
// 	CodeSessionTerminationAnswer           = 275
// 	CodeSTA                                = 275
// 	CodeUserAuthorizationRequest           = 283
// 	CodeUAR                                = 283
// 	CodeUserAuthorizationAnswer            = 283
// 	CodeUAA                                = 283
// 	CodeServerAssignmentRequest            = 284
// 	CodeSAR                                = 284
// 	CodeServerAssignmentAnswer             = 284
// 	CodeSAA                                = 284
// 	CodeLocationInfoRequest                = 285
// 	CodeLIR                                = 285
// 	CodeLocationInfoAnswer                 = 285
// 	CodeLIA                                = 285
// 	CodeMultimediaAuthRequest              = 286
// 	CodeMAR                                = 286
// 	CodeMultimediaAuthAnswer               = 286
// 	CodeMAA                                = 286
// 	CodeRegistrationTerminationRequest     = 287
// 	CodeRTR                                = 287
// 	CodeRegistrationTerminationAnswer      = 287
// 	CodeRTA                                = 287
// 	CodePushProfileRequest                 = 288
// 	CodePPR                                = 288
// 	CodePushProfileAnswer                  = 288
// 	CodePPA                                = 288
// 	Code3GPPUserAuthorizationRequest       = 300
// 	Code3GPPUAR                            = 300
// 	Code3GPPUserAuthorizationAnswer        = 300
// 	Code3GPPUAA                            = 300
// 	Code3GPPServerAssignmentRequest        = 301
// 	Code3GPPSAR                            = 301
// 	Code3GPPServerAssignmentAnswer         = 301
// 	Code3GPPSAA                            = 301
// 	Code3GPPLocationInfoRequest            = 302
// 	Code3GPPLIR                            = 302
// 	Code3GPPLocationInfoAnswer             = 302
// 	Code3GPPLIA                            = 302
// 	Code3GPPMultimediaAuthRequest          = 303
// 	Code3GPPMAR                            = 303
// 	Code3GPPMultimediaAuthAnswer           = 303
// 	Code3GPPMAA                            = 303
// 	Code3GPPRegistrationTerminationRequest = 304
// 	Code3GPPRTR                            = 304
// 	Code3GPPRegistrationTerminationAnswer  = 304
// 	Code3GPPRTA                            = 304
// 	Code3GPPPushProfileRequest             = 305
// 	Code3GPPPPR                            = 305
// 	Code3GPPPushProfileAnswer              = 305
// 	Code3GPPPPA                            = 305
// 	CodeUserDataRequest                    = 306
// 	CodeUDR                                = 306
// 	CodeUserDataAnswer                     = 306
// 	CodeUDA                                = 306
// 	CodeProfileUpdateRequest               = 307
// 	CodePUR                                = 307
// 	CodeProfileUpdateAnswer                = 307
// 	CodePUA                                = 307
// 	CodeSubscribeNotificationsRequest      = 308
// 	CodeSNR                                = 308
// 	CodeSubscribeNotificationsAnswer       = 308
// 	CodeSNA                                = 308
// 	CodePushNotificationRequest            = 309
// 	CodePNR                                = 309
// 	CodePushNotificationAnswer             = 309
// 	CodePNA                                = 309
// 	CodeBootstrappingInfoRequest           = 310
// 	CodeBIR                                = 310
// 	CodeBootstrappingInfoAnswer            = 310
// 	CodeBIA                                = 310
// 	CodeMessageProcessRequest              = 311
// 	CodeMPR                                = 311
// 	CodeMessageProcessAnswer               = 311
// 	CodeMPA                                = 311
// 	CodeUpdateLocationRequest              = 316
// 	CodeULR                                = 316
// 	CodeUpdateLocationAnswer               = 316
// 	CodeULA                                = 316
// 	CodeCancelLocationRequest              = 317
// 	CodeCLR                                = 317
// 	CodeCancelLocationAnswer               = 317
// 	CodeCLA                                = 317
// 	CodeAuthenticationInformationRequest   = 318
// 	CodeAIR                                = 318
// 	CodeAuthenticationInformationAnswer    = 318
// 	CodeAIA                                = 318
// 	CodeInsertSubscriberDataRequest        = 319
// 	CodeISDR                               = 319
// 	CodeInsertSubscriberDataAnswer         = 319
// 	CodeISDA                               = 319
// 	CodeDeleteSubscriberDataRequest        = 320
// 	CodeDSDR                               = 320
// 	CodeDeleteSubscriberDataAnswer         = 320
// 	CodeDSDA                               = 320
// 	CodePurgeUERequest                     = 321
// 	CodePER                                = 321
// 	CodePurgeUEAnswer                      = 321
// 	CodePEA                                = 321
// 	CodeNotifyRequest                      = 323
// 	CodeNR                                 = 323
// 	CodeNotifyAnswer                       = 323
// 	CodeNA                                 = 323
// 	CodeProvideLocationRequest             = 8388620
// 	CodePLR                                = 8388620
// 	CodeProvideLocationAnswer              = 8388620
// 	CodePLA                                = 8388620
// 	CodeRoutingInfoRequest                 = 8388622
// 	CodeRIR                                = 8388622
// 	CodeRoutingInfoAnswer                  = 8388622
// 	CodeRIA                                = 8388622
// 	CodeAAMobileNodeRequest                = 260
// 	CodeAMR                                = 260
// 	CodeAAMobileNodeAnswer                 = 260
// 	CodeAMA                                = 260
// 	CodeHomeAgentMIPRequest                = 262
// 	CodeHAR                                = 262
// 	CodeHomeAgentMIPAnswer                 = 262
// 	CodeHAA                                = 262
// )

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

//type MessageAttributes struct {
// 	msgName          string
// 	msgAbbrv         string
// 	msgCode          Uint24
// 	msgIsRequest     bool
// 	msgMandatoryAvps []*AVPAttribute
//}

//
// func NewMessageAttribute(name string, abbrv string, code Uint24,
// 	is_request bool, mandatoryAvps []*AVPAttribute) *MessageAttributes {
// 	return &MessageAttributes{name, abbrv, code, is_request, mandatoryAvps}
// }

// FindAVPByCode returns the first instance of the identified AVP associated
// with the current Message, or nil if the Message has no instances of the AVP
func (m *Message) FindAVPByCode(code Uint24) *AVP {
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

// // MessageIsCER returns true if m is a Capabilities Exchange Request; false otherwise
// func MessageIsCER(m *Message) bool {
// 	return m.IsRequest() && m.AppID == 0 && m.Code == 257
// }
//
// // MessageIsCEA returns true if m is a Capabilities Exchange Answer; false otherwise
// func MessageIsCEA(m *Message) bool {
// 	return !m.IsRequest() && m.AppID == 0 && m.Code == 257
// }
//
// // MessageIsDWR returns true if m is a Device Watchdog Request; false otherwise
// func MessageIsDWR(m *Message) bool {
// 	return m.IsRequest() && m.AppID == 0 && m.Code == 280
// }
//
// // MessageIsDWA returns true if m is a Device Watchdog Answer; false otherwise
// func MessageIsDWA(m *Message) bool {
// 	return !m.IsRequest() && m.AppID == 0 && m.Code == 280
// }
//
// // MessageIsDPR returns true if m is a Disconnect Peer Request; false otherwise
// func MessageIsDPR(m *Message) bool {
// 	return m.IsRequest() && m.AppID == 0 && m.Code == 282
// }
//
// // MessageIsDPA returns true if m is a Disconnect Peer Answer; false otherwise
// func MessageIsDPA(m *Message) bool {
// 	return !m.IsRequest() && m.AppID == 0 && m.Code == 282
// }

// MessageStreamReader simplifies the reading of an octet stream which must be
// converted to one or more diameter.Message objects.  Generally, a new
// MessageStreamReader is created, then ReceiveBytes is repeatedly called on
// an input stream (which must be in network byte order).  This method will
// return diameter.Message objects as they can be extracted, and return any
// remaining bytes not consumed by produced messages
type MessageStreamReader struct {
	incomingBuffer *[]byte
}

// NewMessageStreamReader creates a new MessageStreamReader object
func NewMessageStreamReader() *MessageStreamReader {
	return new(MessageStreamReader)
}

// ReceiveBytes returns one or more diameter.Message objects read from the incoming
// byte stream.  Return nil if no Message is yet found.  Return error on malformed
// byte stream.  If an error is returned, subsequent calls are no longer reliable.
func (reader *MessageStreamReader) ReceiveBytes(incoming []byte) ([]*Message, error) {
	mlist := list.New()

	// XXX: does it make sense to shrink the self.incoming_buffer after a complete message is found
	//      if the buffer exceeds a specific size?  There's a tradeoff here: on the one hand, if
	//      a really big message arrives, then the large chunk of memory is allocated (up to 2**24-1 bytes).
	//      If all other messages are much smaller (say, <= 4k), then that allocated memory is hanging
	//      around for no value.  On the other hand, if really large messages periodically arrive, then
	//      there is high CPU overhead to repeatedly allocating and deallocating the memory chunk.
	for {
		var m *Message
		var err error
		m, incoming, err = reader.iterateMessageStream(incoming)

		if err != nil {
			return nil, err
		} else if m != nil {
			mlist.PushBack(m)
		} else {
			m := make([]*Message, mlist.Len())
			i := 0
			for e := mlist.Front(); e != nil; e = e.Next() {
				m[i] = e.Value.(*Message)
				i++
			}
			return m, nil
		}
	}
}

// Iterate through an incoming stream and attempt to extract a Message, if there are enough
// bytes in the stream.  If not, return (nil, incoming, nil).  If the stream is malformed for
// a message, return (nil, incoming, error). If there is at least enough bytes for a message
// and the stream is well-formed, return (m, remainder, nil), where m is a Message and
// remainder is a slice of incoming, starting one byte after the extracted message.
func (reader MessageStreamReader) iterateMessageStream(incoming []byte) (*Message, []byte, error) {
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
