package diameter

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type PeerType int

const (
	Initator  PeerType = iota
	Responder PeerType = iota
)

type PeerConnectionInformation struct {
	RemoteAddress     *net.IP
	RemotePort        uint16
	TransportProtocol string
	LocalAddress      *net.IP
	LocalPort         uint16
}

type Peer struct {
	TypeOfPeer                  PeerType
	PeerCapabilitiesInformation *CapabiltiesExchangeInformation
	ConnectionInformation       PeerConnectionInformation
}

type PeerHandler struct {
	peer                   *Peer
	connection             net.Conn
	diameterByteReader     *MessageByteReader
	eventChannel           chan<- *NodeEvent
	flowReadBuffer         []byte
	myCapabilities         *CapabiltiesExchangeInformation
	nextHopByHopIdentifier uint32
	nextEndToEndIdentifier uint32
}

func NewHandlerForInitiatorPeer(flowConnection net.Conn, eventChannel chan<- *NodeEvent) *PeerHandler {
	return newPeerHandler(flowConnection, Initator, eventChannel)
}

func NewHandlerForResponderPeer(flowConnection net.Conn, eventChannel chan<- *NodeEvent) *PeerHandler {
	return newPeerHandler(flowConnection, Responder, eventChannel)
}

func (handler *PeerHandler) WithCapabilities(capabilities *CapabiltiesExchangeInformation) *PeerHandler {
	handler.myCapabilities = &(*capabilities)
	return handler
}

func (handler *PeerHandler) SeedIdentifiers() (*PeerHandler, error) {
	initialEndToEndIdentifier, err := generateIdentifierSeedValue()
	if err != nil {
		return handler, fmt.Errorf("failed to generate cryptographic seed for end-to-end identifier: %s", err.Error())
	}

	initialHopByHopIdentifier, err := generateIdentifierSeedValue()
	if err != nil {
		return handler, fmt.Errorf("failed to generate cryptographic seed for hop-by-hop identifier: %s", err.Error())
	}

	handler.nextEndToEndIdentifier = initialEndToEndIdentifier
	handler.nextHopByHopIdentifier = initialHopByHopIdentifier

	return handler, nil
}

func (handler *PeerHandler) WithSeededIdentifiers() (*PeerHandler, error) {
	return handler.SeedIdentifiers()
}

func newPeerHandler(flowConnection net.Conn, typeOfPeer PeerType, eventChannel chan<- *NodeEvent) *PeerHandler {
	var localIPAddr, remoteIPAddr *net.IP
	var localPort, remotePort uint16

	if flowConnection.LocalAddr().Network() == "tcp" {
		localTCPAddr := flowConnection.LocalAddr().(*net.TCPAddr)
		remoteTCPAddr := flowConnection.RemoteAddr().(*net.TCPAddr)

		localIPAddr = &localTCPAddr.IP
		localPort = uint16(localTCPAddr.Port)
		remoteIPAddr = &remoteTCPAddr.IP
		remotePort = uint16(remoteTCPAddr.Port)
	} else {
		localIPAddr, localPort = extractIPAddressAndPortFromAddrNetworkString(flowConnection.LocalAddr().String())
		remoteIPAddr, remotePort = extractIPAddressAndPortFromAddrNetworkString(flowConnection.RemoteAddr().String())
	}

	return &PeerHandler{
		peer: &Peer{
			TypeOfPeer:                  typeOfPeer,
			PeerCapabilitiesInformation: nil,
			ConnectionInformation: PeerConnectionInformation{
				RemoteAddress:     remoteIPAddr,
				RemotePort:        remotePort,
				LocalAddress:      localIPAddr,
				LocalPort:         localPort,
				TransportProtocol: flowConnection.LocalAddr().Network(),
			},
		},
		connection:         flowConnection,
		eventChannel:       eventChannel,
		diameterByteReader: NewMessageByteReader(),
		flowReadBuffer:     make([]byte, 9000),
	}
}

func generateIdentifierSeedValue() (uint32, error) {
	randBytes := make([]byte, 3)
	if _, err := rand.Read(randBytes); err != nil {
		return 0, err
	}

	var seedLower20 uint32 = (uint32(randBytes[0]) << 12) | (uint32(randBytes[1]) << 4) | (uint32(randBytes[2] >> 4))
	var seed uint32 = (uint32(time.Now().Unix()) << 20) | seedLower20

	return seed, nil
}

func extractIPAddressAndPortFromAddrNetworkString(networkAddress string) (*net.IP, uint16) {
	parts := strings.Split(networkAddress, ":")
	if len(parts) < 2 {
		panic(fmt.Sprintf("provided invalid IP transport address: %s", networkAddress))
	}

	portAsString := parts[len(parts)-1]
	portAsUint64, err := strconv.ParseUint(portAsString, 10, 16)
	if err != nil {
		panic(fmt.Sprintf("provided invalid IP transport address (port xlat failed): %s", portAsString))
	}

	ipAsString := strings.Join(parts[:len(parts)-1], ":")
	ipAsString = strings.Trim(ipAsString, "[]")

	ipAddr := net.ParseIP(ipAsString)
	if ipAddr == nil {
		panic(fmt.Sprintf("provided invalid IP transport address (IP xlat failed): %s", ipAsString))
	}

	return &ipAddr, uint16(portAsUint64)
}

func (handler *PeerHandler) StartHandling() {
	defer handler.connection.Close()

	if handler.myCapabilities == nil {
		panic("attempt to StartHandling without having set local agent capabilities")
	}

	if err := handler.completeCapabilitiesExchangeWithPeer(); err != nil {
		return
	}

}

func (handler *PeerHandler) completeCapabilitiesExchangeWithPeer() error {
	if handler.peer.TypeOfPeer == Initator {
		cer := handler.waitForCER()
		if cer == nil {
			return fmt.Errorf("failed to receive CER")
		}

		ceaToSendInResponse := handler.myCapabilities.MakeCEA().BecomeAnAnswerBasedOnTheRequestMessage(cer)

		err := handler.SendMessageToPeer(ceaToSendInResponse)
		if err != nil {
			handler.sendFatalTransportErrorEvent(err)
			handler.sendCapabilitiesExchangeFailureEvent(fmt.Errorf("failed to send CEA"))
			return err
		}

		return nil
	}

	// peer is Responder
	cer := handler.myCapabilities.MakeCER()
	handler.populateMessageIdentifiers(cer)

	err := handler.SendMessageToPeer(cer)
	if err != nil {
		handler.sendFatalTransportErrorEvent(err)
		handler.sendCapabilitiesExchangeFailureEvent(fmt.Errorf("failed to send CER"))
	}

	cea := handler.waitForCEA()
	if cea == nil {
		return fmt.Errorf("failed to receive CEA")
	}

	handler.peer.PeerCapabilitiesInformation, err = extractCapabilitiesForPeerFromCapabilitiesExchangeMessage(cea)
	if err != nil {
		handler.sendCapabilitiesExchangeFailureEvent(err)
		return err
	}

	return nil
}

func extractCapabilitiesForPeerFromCapabilitiesExchangeMessage(message *Message) (*CapabiltiesExchangeInformation, error) {
	var originHost, originRealm, productName string
	var hostIPAddresses []*net.IPAddr
	var vendorID uint32

	var foundOriginHost, foundOriginRealm, foundProductName, foundHostIPAddresses, foundVendorID bool

	additionalAVPs := make([]*AVP, 10)

	for _, avp := range message.Avps {
		switch avp.Code {
		case 264:
			originHost = string(avp.Data)
			foundOriginHost = true

		case 296:
			originRealm = string(avp.Data)
			foundOriginRealm = true

		case 269:
			productName = string(avp.Data)
			foundProductName = true

		case 266:
			wrappedVendorID, err := avp.ConvertDataToTypedData(Unsigned32)
			if err != nil {
				return nil, fmt.Errorf("Vendor-ID AVP is improperly formatted")
			}
			vendorID = wrappedVendorID.(uint32)
			foundVendorID = true

		case 257:
			wrappedIP, err := avp.ConvertDataToTypedData(Address)
			if err != nil {
				return nil, fmt.Errorf("Host-IP-Address AVP contains invalid data: %s", err.Error())
			}

			ip := wrappedIP.(*net.IP)
			hostIPAddresses = append(hostIPAddresses, &net.IPAddr{IP: *ip, Zone: ""})

		default:
			additionalAVPs = append(additionalAVPs, avp)
		}
	}

	if !foundOriginHost {
		return nil, fmt.Errorf("peer asserted no Origin-Host")
	}
	if !foundOriginRealm {
		return nil, fmt.Errorf("peer asserted no Origin-Realm")
	}
	if !foundHostIPAddresses {
		return nil, fmt.Errorf("peer asserted no Host-IP-Addresses")
	}
	if !foundProductName {
		return nil, fmt.Errorf("peer asserted no Product-Name")
	}
	if !foundVendorID {
		return nil, fmt.Errorf("peer asserted no Vendor-ID")
	}

	return &CapabiltiesExchangeInformation{
		OriginHost:                 originHost,
		OriginRealm:                originRealm,
		HostIPAddresses:            hostIPAddresses,
		VendorID:                   vendorID,
		ProductName:                productName,
		AdditionalAVPsToSendToPeer: additionalAVPs,
	}, nil
}

func (handler *PeerHandler) populateMessageIdentifiers(message *Message) {
	message.HopByHopID = handler.nextHopByHopIdentifier
	message.EndToEndID = handler.nextEndToEndIdentifier

	handler.nextEndToEndIdentifier++
	handler.nextEndToEndIdentifier++
}

func (handler *PeerHandler) waitForCER() (cerMessage *Message) {
	var messages []*Message

	for {
		bytesRead, err := handler.connection.Read(handler.flowReadBuffer)
		if err != nil {
			handler.sendTransportReadErrorEvent(err)
			return nil
		}

		messages, err = handler.diameterByteReader.ReceiveBytes(handler.flowReadBuffer[:bytesRead])
		if err != nil {
			handler.sendUnableToParseIncomingMessageStreamEvent(err)
			return nil
		}

		if len(messages) > 0 {
			break
		}
	}

	if messageIsNotACER(messages[0]) {
		handler.sendCapabilitiesExchangeFailureEvent(fmt.Errorf("first message from peer is not a CER"))
		return nil
	}

	if len(messages) > 1 {
		handler.sendCapabilitiesExchangeFailureEvent(fmt.Errorf("peer sent messages before completing capabilities-exchange"))
		return nil
	}

	return messages[0]
}

func (handler *PeerHandler) waitForCEA() (ceaMessage *Message) {
	var message *Message

	for {
		bytesRead, err := handler.connection.Read(handler.flowReadBuffer)
		if err != nil {
			handler.sendTransportReadErrorEvent(err)
			return nil
		}

		message, err = handler.diameterByteReader.ReceiveBytesButReturnAtMostOneMessage(handler.flowReadBuffer[:bytesRead])
		if err != nil {
			handler.sendUnableToParseIncomingMessageStreamEvent(err)
			return nil
		}

		if message != nil {
			break
		}
	}

	if messageIsNotACEA(message) {
		handler.sendCapabilitiesExchangeFailureEvent(fmt.Errorf("first message from peer is not a CEA"))
		return nil
	}

	return message
}

func (handler *PeerHandler) sendCapabilitiesExchangeAnswerBasedOnCER(cer *Message) error {
	cea := handler.generateCEA().BecomeAnAnswerBasedOnTheRequestMessage(cer)

	err := handler.SendMessageToPeer(cea)
	if err != nil {
		handler.sendFatalTransportErrorEvent(err)
		return fmt.Errorf("transport error occured after sending CEA")
	}

	return nil
}

func (handler *PeerHandler) sendFatalTransportErrorEvent(err error) {
	handler.eventChannel <- &NodeEvent{
		Type:       FatalTransportError,
		Peer:       handler.peer,
		Connection: handler.connection,
		Error:      err,
	}
}

func (handler *PeerHandler) generateCEA() *Message {
	return NewMessage(0, 257, 0, 0, 0, nil, nil)
}

func (handler *PeerHandler) sendCapabilitiesExchangeFailureEvent(err error) {
	handler.eventChannel <- &NodeEvent{
		Type:       CapabilitiesExchangeFailed,
		Peer:       handler.peer,
		Connection: handler.connection,
		Error:      err,
	}
}

func messageIsNotACER(message *Message) bool {
	return message.AppID != 0 || message.Code != 257 || !message.IsRequest()
}

func messageIsNotACEA(message *Message) bool {
	return message.AppID != 0 || message.Code != 257 || message.IsRequest()
}

func (handler *PeerHandler) sendUnableToParseIncomingMessageStreamEvent(readError error) {
	handler.eventChannel <- &NodeEvent{
		Type:       UnableToParseIncomingMessageStream,
		Peer:       handler.peer,
		Connection: handler.connection,
		Error:      readError,
	}
}

func (handler *PeerHandler) sendTransportReadErrorEvent(err error) {
	if err == io.EOF {
		handler.eventChannel <- &NodeEvent{
			Type:       TransportClosed,
			Peer:       handler.peer,
			Connection: handler.connection,
		}
	} else {
		handler.eventChannel <- &NodeEvent{
			Type:       FatalTransportError,
			Peer:       handler.peer,
			Connection: handler.connection,
			Error:      err,
		}
	}
}

func (handler *PeerHandler) SendMessageToPeer(message *Message) error {
	_, err := handler.connection.Write(message.Encode())
	return err
}

func (handler *PeerHandler) CloseDiameterFlow() error {
	return nil
}

func (handler *PeerHandler) Terminate() error {
	return nil
}

type IncomingPeerListener struct {
	listener                net.Listener
	capabilitiesInformation *CapabiltiesExchangeInformation
	cloneableCEA            *Message
}

func NewIncomingPeerListener(usingUnderlyingListener net.Listener, usingCapabilitiesInformation CapabiltiesExchangeInformation) *IncomingPeerListener {
	copyOfCapabilitiesInformation := usingCapabilitiesInformation
	return &IncomingPeerListener{
		listener:                usingUnderlyingListener,
		capabilitiesInformation: &copyOfCapabilitiesInformation,
		cloneableCEA:            (&copyOfCapabilitiesInformation).MakeCEAUsingResultCode(2002),
	}
}

func (peerListener *IncomingPeerListener) StartListening(eventChannel chan<- *NodeEvent) {
	for {
		flowConnection, err := peerListener.listener.Accept()
		if err != nil {
			eventChannel <- &NodeEvent{
				Type:       RecoverableTransportError,
				Connection: flowConnection,
				Error:      err,
			}
		}

		peerHandler, err := NewHandlerForInitiatorPeer(flowConnection, eventChannel).WithCapabilities(peerListener.capabilitiesInformation).WithSeededIdentifiers()
		if err != nil {
			eventChannel <- &NodeEvent{
				Type:  InternalFailure,
				Error: fmt.Errorf("failed to create PeerHandler: %s", err.Error()),
			}

			flowConnection.Close()
			continue
		}

		go peerHandler.StartHandling()
	}
}

func (peerListener *IncomingPeerListener) StopListening() error {
	return nil
}
