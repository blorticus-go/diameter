package diameter

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type peerType int

const (
	peerIsInitiator peerType = iota
	peerIsResponder peerType = iota
)

type PeerConnectionInformation struct {
	RemoteAddress     *net.IP
	RemotePort        uint16
	TransportProtocol string
	LocalAddress      *net.IP
	LocalPort         uint16
}

type Peer struct {
	TypeOfPeer                  peerType
	PeerCapabilitiesInformation *CapabiltiesExchangeInformation
	ConnectionInformation       PeerConnectionInformation
}

type PeerHandler struct {
	peer                 *Peer
	connection           net.Conn
	diameterStreamReader *MessageStreamReader
	eventChannel         chan<- *NodeEvent
	flowReadBuffer       []byte
}

func NewHandlerForInitiatorPeer(flowConnection net.Conn, eventChannel chan<- *NodeEvent) *PeerHandler {
	return newPeerHandler(flowConnection, peerIsInitiator, eventChannel)
}

func NewHandlerForResponderPeer(flowConnection net.Conn, eventChannel chan<- *NodeEvent) *PeerHandler {
	return newPeerHandler(flowConnection, peerIsResponder, eventChannel)
}

func newPeerHandler(flowConnection net.Conn, typeOfPeer peerType, eventChannel chan<- *NodeEvent) *PeerHandler {
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
		connection:           flowConnection,
		eventChannel:         eventChannel,
		diameterStreamReader: NewMessageStreamReader(),
		flowReadBuffer:       make([]byte, 9000),
	}
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

func (handler *PeerHandler) Start(localAgentCapabilities *CapabiltiesExchangeInformation) {
	defer handler.connection.Close()

	if err := handler.completeCapabilitesExchangeWhenRemotePeerInitiatesFlow(ceaToSendInResponse); err != nil {
		return
	}

}

func (handler *PeerHandler) completeCapabilitesExchangeWhenRemotePeerInitiatesFlow(ceaToSendInResponse *Message) error {
	cer := handler.waitForCER()
	if cer == nil {
		return fmt.Errorf("failed to receive CER")
	}

	ceaToSendInResponse.MakeMeIntoAnAnswerForTheRequestMessage(cer)

	err := handler.SendMessageToPeer(ceaToSendInResponse)
	if err != nil {
		handler.sendFatalTransportErrorEvent(err)
		handler.sendCapabilitiesExchangeFailureEvent(fmt.Errorf("failed to send CEA"))
		return err
	}

	return nil
}

func (handler *PeerHandler) waitForCER() (cerMessage *Message) {
	var messages []*Message

	for {
		bytesRead, err := handler.connection.Read(handler.flowReadBuffer)
		if err != nil {
			handler.sendTransportReadErrorEvent(err)
			return nil
		}

		messages, err = handler.diameterStreamReader.ReceiveBytes(handler.flowReadBuffer[:bytesRead])
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

func (handler *PeerHandler) sendCapabilitiesExchangeAnswerBasedOnCER(cer *Message) error {
	cea := handler.generateCEA().MakeMeIntoAnAnswerForTheRequestMessage(cer)

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
	return message.AppID != 0 || message.Code != 257 && !message.IsRequest()
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

		peer := NewHandlerForInitiatorPeer(flowConnection, eventChannel)
		go peer.StartStateMachineExpectingCER(peerListener.cloneableCEA.Clone())
	}
}

func (peerListener *IncomingPeerListener) StopListening() error {
	return nil
}
