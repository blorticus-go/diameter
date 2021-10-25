package diameter

import "net"

// A Diameter Node implements can listen for an receive incoming Diameter flows, and
// can create outgoing Diameter flows toward other nodes.  For each flow, the node
// implements the Diameter base application state machine.  When state machine transitions
// occur and messages are sent or received, events are raised that can be intercepted.

// CapabiltiesExchangeInformation contains information sent to peer nodes during
// the capabilities exchange, or received from peer nodes during the capabilities exchange
type CapabiltiesExchangeInformation struct {
	OriginHost                 string
	OriginRealm                string
	HostIPAddresses            []*net.IPAddr
	VendorID                   uint32
	ProductName                string
	AdditionalAVPsToSendToPeer []*AVP
}

// MakeCER creates a CER using the exchange information values.
func (info *CapabiltiesExchangeInformation) MakeCER() *Message {
	hostIPAddrAvps := make([]*AVP, len(info.HostIPAddresses))
	for _, hostIPAddress := range info.HostIPAddresses {
		hostIPAddrAvps = append(hostIPAddrAvps, NewTypedAVP(257, 0, true, Address, hostIPAddress))
	}

	clonedAdditionalAvps := make([]*AVP, len(info.AdditionalAVPsToSendToPeer))
	for _, avpToClone := range info.AdditionalAVPsToSendToPeer {
		clonedAdditionalAvps = append(clonedAdditionalAvps, avpToClone.Clone())
	}

	msgAvps := make([]*AVP, 4+len(hostIPAddrAvps)+len(clonedAdditionalAvps))

	msgAvps = append(msgAvps,
		NewTypedAVP(264, 0, true, DiamIdent, info.OriginHost),
		NewTypedAVP(296, 0, true, DiamIdent, info.OriginRealm))

	msgAvps = append(msgAvps, hostIPAddrAvps...)

	msgAvps = append(msgAvps,
		NewTypedAVP(266, 0, true, Unsigned32, info.VendorID),
		NewTypedAVP(269, 0, true, UTF8String, info.ProductName))

	msgAvps = append(msgAvps, clonedAdditionalAvps...)

	return NewMessage(MsgFlagRequest, 257, 0, 0, 0, msgAvps, []*AVP{})
}

// MakeCEAUsingResultCode makes a CEA using the exchange information values, with a
// Result-Code set to the provided value.
func (info *CapabiltiesExchangeInformation) MakeCEAUsingResultCode(resultCode uint32) *Message {
	hostIPAddrAvps := make([]*AVP, len(info.HostIPAddresses))
	for _, hostIPAddress := range info.HostIPAddresses {
		hostIPAddrAvps = append(hostIPAddrAvps, NewTypedAVP(257, 0, true, Address, hostIPAddress))
	}

	clonedAdditionalAvps := make([]*AVP, len(info.AdditionalAVPsToSendToPeer))
	for _, avpToClone := range info.AdditionalAVPsToSendToPeer {
		clonedAdditionalAvps = append(clonedAdditionalAvps, avpToClone.Clone())
	}

	msgAvps := make([]*AVP, 5+len(hostIPAddrAvps)+len(clonedAdditionalAvps))

	msgAvps = append(msgAvps,
		NewTypedAVP(268, 0, true, Unsigned32, resultCode),
		NewTypedAVP(264, 0, true, DiamIdent, info.OriginHost),
		NewTypedAVP(296, 0, true, DiamIdent, info.OriginRealm))

	msgAvps = append(msgAvps, hostIPAddrAvps...)

	msgAvps = append(msgAvps,
		NewTypedAVP(266, 0, true, Unsigned32, info.VendorID),
		NewTypedAVP(269, 0, true, UTF8String, info.ProductName))

	msgAvps = append(msgAvps, clonedAdditionalAvps...)

	return NewMessage(MsgFlagRequest, 257, 0, 0, 0, msgAvps, []*AVP{})
}

// MakeCEA is shorthand for MakeCeaUsingResultCode(2002).
func (info *CapabiltiesExchangeInformation) MakeCEA() *Message {
	return info.MakeCEAUsingResultCode(2002)
}

// NodeListener contains information describing a listener for incoming peer flows
type NodeListener struct {
	listener                               net.Listener
	defaultCapabilitiesExchangeInformation *CapabiltiesExchangeInformation
}

// NewNodeListener creates attaches a listener to the node, and provides information that
// should be asserted to any incoming peer when the peer initiates a flow against the listener.
func NewNodeListener(listener net.Listener, informationAssertedInCapabilitiesAnswer *CapabiltiesExchangeInformation) *NodeListener {
	return &NodeListener{listener, informationAssertedInCapabilitiesAnswer}
}

// PeerFlowInformation contains information for an active connection flow with a peer node.
type PeerFlowInformation struct {
	PeerAddress       *net.IPAddr
	PeerPort          uint16
	MyAddress         *net.IPAddr
	MyPort            uint16
	TransportProtocol string // "tcp" or "sctp"
}

// NodeEventType describes the types of events that are raised in relationship to a node's operation.
type NodeEventType int

// NodeEvent is an event related to the node's operation.
type NodeEvent struct {
	Type       NodeEventType
	Peer       *Peer
	Connection net.Conn
	Message    *Message
	Error      error
}

// PeerSpecificError connects an error to a specific peer.
type PeerSpecificError struct {
	Peer  *Peer
	Error error
}

const (
	FatalTransportError                        NodeEventType = -1
	RecoverableTransportError                  NodeEventType = -2
	MessageDeliveryError                       NodeEventType = -3
	CapabilitiesExchangeFailed                 NodeEventType = -4
	WatchdogTimeoutExceeded                    NodeEventType = -5
	IncomingTransportAttemptBlocked            NodeEventType = -6
	IncomingPeerBlockedOnCapbilitiesExchange   NodeEventType = -7
	TimedOutConnectingToPeer                   NodeEventType = -8
	ListenerFailed                             NodeEventType = -9
	DuplicationPeerFlowRejected                NodeEventType = -10
	UnableToParseIncomingMessageStream         NodeEventType = -11
	InternalFailure                            NodeEventType = -12
	CapabilitiesExchangeSuccessfullyCompleted  NodeEventType = 1
	CapabilitiesRequestReceivedFromPeer        NodeEventType = 2
	ReceivedDiameterMessageFromPeer            NodeEventType = 3
	SuccessfullyDeliveredDiameterMessageToPeer NodeEventType = 4
	PeerSentDisconnectRequest                  NodeEventType = 5
	PeerFullyDisconnected                      NodeEventType = 6
	ReceivedCapabilitiesExchangeRequest        NodeEventType = 7
	ReceivedWatchdogRequest                    NodeEventType = 8
	WatchdogSuccessful                         NodeEventType = 9
	TransportClosed                            NodeEventType = 10
)

// Node is an entity that implements the Diameter base protocol state machine
// for Peer node flows.  It can both listen for incoming flows and initiate
// outbound flows.
type Node struct {
	activeListeners []*NodeListener
	eventChannel    chan *NodeEvent
}

// NewNode creates a new Diameter node.  The provided default capabilities exchange assertion
// will be used in any capabilities exchange request if it is not overridden when the
// request for the outbound connection to a peer is made.
func NewNode(defaultCapabilitiesExchangeAssertion CapabiltiesExchangeInformation) *Node {
	return &Node{
		activeListeners: make([]*NodeListener, 0, 10),
		eventChannel:    make(chan *NodeEvent, 100),
	}
}

// AddListener adds a listener and the capabilities exchange assertion that should be used
// when a new incoming flow is initiated to the listener and a CER is received on that flow.
// Returns the node on which the operation is being applied so that it can be chained with
// other calls, if desired.
func (node *Node) AddListener(listener *NodeListener) *Node {
	node.activeListeners = append(node.activeListeners, listener)
	return node
}

// AddListeners is the same as AddListener() but adds multiple listeners at the same time.
func (node *Node) AddListeners(listeners []*NodeListener) *Node {
	node.activeListeners = append(node.activeListeners, listeners...)
	return node
}

// Start starts the node.  It returns a channel of events that are produced by this node.
func (node *Node) Start() chan<- *NodeEvent {
	return node.eventChannel
}

// StopListener stops a listener from listening.  It does not close any flows initiated
// through the listener.  This is a synchronous action.
func (node *Node) StopListener(listener *NodeListener) error {
	return nil
}

// StopAllListeners stops all listener from listening.  It does not close any flows initiated
// through the listeners.  This is a synchronous action.
func (node *Node) StopAllListeners() error {
	return nil
}

// ChangeDefaultOutboundCapabilitiesInformationTo changes the default information asserted
// in the capabilities exchange request sent by this node when it initiates an outbound flow.
func (node *Node) ChangeDefaultOutboundCapabilitiesInformationTo(defaultInformation CapabiltiesExchangeInformation) *Node {
	return node
}

// ConnectToPeer synchronously attempts to complete a capabilities exchange over the provided
// connection.  Returns a Peer object on success, or an error on failure.
func (node *Node) ConnectToPeer(usingConnection net.Conn) (*Peer, error) {
	return nil, nil
}

// ConnectToPeerAsynchronously is the same as ConnectToPeer(), but does so asynchronously.
// It launches a goroutine then immediately returns.  The attempt will generate generate events.
func (node *Node) ConnectToPeerAsynchronously(usingConnection net.Conn) {
}

// ConnectToPeerUsingCapabilities is the same as ConnectToPeer(), but instead of using the
// default outgoing capabilities assertion, it uses the provided information.
func (node *Node) ConnectToPeerUsingCapabilities(usingConnection net.Conn, information CapabiltiesExchangeInformation) (*Peer, error) {
	return nil, nil
}

// ConnectToPeerUsingCapabilitiesAsynchronously is the same as ConnectToPeerAsynchronously(), but
// rather than using the default outgoing capabilities assertion, it uses the provided information.
func (node *Node) ConnectToPeerUsingCapabilitiesAsynchronously(usingConnection net.Conn, information CapabiltiesExchangeInformation) {
}

// DisconnectFromPeer sends a DPR toward the named Peer.  There are two cases where this is valid:
// 1. to initiate a disconnect (i.e., signaling that the node should send a DPR); and 2. after a DPR
// is received by a Peer (and thus, this would be called after receiving the event PeerSentDisconnectRequest).
// If this is for case 1 (node sends DPR), then the node will set the Disconnect-Cause to DO_NOT_WANT_TO_TALK_TO_YOU.
// If this is case 1 (nodes sends DPR), then on the receipt of a DPA, the node will attempt to close the underlying
// connection.  If this is for case 2 (responding to DPR with a DPA), the ndoe will send the DPA then attempt to
// close the underlying connection.
func (node *Node) DisconnectFromPeer(peer *Peer) error {
	return nil
}

// DisconnectFromPeerAsynchronously does the same as DisconnectFromPeer(), but does so asynchronously.
// It launches a goroutine then immediately returns.  The attempt will generate events.
func (node *Node) DisconnectFromPeerAsynchronously(peer *Peer) {
}

// DisconnectFromPeerWithCustomInformation is the same as DisconnectFromPeer() but it sends for the
// Disconnect-Cause the provided value (it is up to the caller to ensure that it is a valid value for
// the Disconnect-Cause enumeration type), and sends any provided additional AVPs.
func (node *Node) DisconnectFromPeerWithCustomInformation(peer *Peer, disconnectCauseValue uint32, additionalAVPs []*AVP) error {
	return nil
}

// DisconnectFromPeerWithCustomInformationAsynchronously does the same as DisconnectFromPeerWithCustomInformation(),
// but does so asynchronously.  It launches a goroutine then immediately returns.  The attempt will generate events.
func (node *Node) DisconnectFromPeerWithCustomInformationAsynchronously(peer *Peer, disconnectCauseValue uint32, additionalAVPs []*AVP) {
}

// DisconnectFromAllPeerFlows attempts to disconnect all peer flows by sending a DPR to each.  It will send
// DO_NOT_WANT_TO_TALK_TO_YOU as the Disconnect-Reason.  It also attempts to close the underlying connection.
// If an error occurs for a flow, it still attempts to continue.  Returns the accumulated set of errors,
// as well as Peer connected to flow on which the error occurred.  Returns nil if no error occurred.
func (node *Node) DisconnectFromAllPeerFlows() []PeerSpecificError {
	return nil
}

// DisconnectAllPeerFlowsAsynchronously does the same as DisconnectFromAllPeerFlows(), but does so
// asynchronously.  It launches a goroutine then immediately returns.  The attempt will generate events.
func (node *Node) DisconnectAllPeerFlowsAsynchronously() {
}

// DisconnectAllPeerFlowsWithCustomInformation does the same as DisconnectFromAllPeerFlows(),
// but sends the provided Disconnect-Cause value (the caller is responsible for ensuring that the value is
// valid for the Disconnect-Cause enumeration) and any desired additional AVPs in the DPR.
func (node *Node) DisconnectAllPeerFlowsWithCustomInformation(disconnectCauseValue uint32, additionalAVPs []*AVP) []PeerSpecificError {
	return nil
}

// DisconnectAllPeerFlowsWithCustomInformationAsynchronously does the same as DisconnectFromAllPeerFlowsWithCustomInformation
// but does so asynchronously.  It launches a goroutine then immediately returns.  The attempt will generate events.
func (node *Node) DisconnectAllPeerFlowsWithCustomInformationAsynchronously(disconnectCauseValue uint32, additionalAVPs []*AVP) {
}

// UnfilterStateMessages signals that Capabilities-Exchange, Diameter-Watchdog and Disconnect-Peer messages that
// are received should be included in the event stream.  By default, messages of this type are supressed.
func (node *Node) UnfilterStateMessages() *Node {
	return nil
}

// FilterOutStateMessages signals that Capabilities-Exchange, Diameter-Watchdog and Disconnect-Peer messages should
// not be included in the event stream.  This is the default behavior.
func (node *Node) FilterOutStateMessages() *Node {
	return nil
}

// AutomaticallyDisconnectPeerWhenPeerSendsDisconnectRequest signals that when a DPR is received on a previously
// accepted flow for the identified peer, a DPA should be automatically sent.  Normally, this is done manually when the
// PeerSentDisconnectRequest is received.
func (node *Node) AutomaticallyDisconnectPeerWhenPeerSendsDisconnectRequest(peer *Peer) error {
	return nil
}

// AutomaticallyDisconnectAnyPeerThatSendsDisconnectRequest signals that when a DPR is received on a previously
// accepted flow for any peer, a DPA should be automatically sent.  Normally, this is done manually when the
// PeerSentDisconnectRequest is received.
func (node *Node) AutomaticallyDisconnectAnyPeerThatSendsDisconnectRequest() *Node {
	return node
}
