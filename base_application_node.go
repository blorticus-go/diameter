package diameter

import "net"

// BaseCapabilities is a name/value structure for NewBaseApplictionNode
type BaseCapabilities struct {
	OriginHost      string
	OriginRealm     string
	HostIPAddresses []*net.IPAddr
	VendorID        uint32
	ProductName     string
}

// Peer represents a remote peer
type Peer struct {
	OriginHost    string
	OriginRealm   string
	RemoteAddress *net.IPAddr
	RemotePort    uint32
	LocalAddress  *net.IPAddr
	LocalPort     uint32
}

// BaseNodeEventMessageType indicates what the type of message is when a BaseApplictionNode
// generates a BaseNodeEventMessage
type BaseNodeEventMessageType int

// These are the BaseClientEventMessage types
const (
	FatalTransportError                       BaseNodeEventMessageType = -1
	RecoverableTransportError                 BaseNodeEventMessageType = -2
	MessageDeliveryError                      BaseNodeEventMessageType = -3
	CapabilitiesExchangeFailed                BaseNodeEventMessageType = -4
	WatchdogTimeoutExceeded                   BaseNodeEventMessageType = -5
	IncomingTransportAttemptBlocked           BaseNodeEventMessageType = -6
	IncomingPeerBlockedOnCapbilitiesExchange  BaseNodeEventMessageType = -7
	TimedOutConnectingToPeer                  BaseNodeEventMessageType = -8
	ListenerFailed                            BaseNodeEventMessageType = -9
	AllListenersHaveFailed                    BaseNodeEventMessageType = -10
	CapabilitiesExchangeSuccessfullyCompleted BaseNodeEventMessageType = 1
	// ReceivedDiameterMessageFromPeer will not include watchdog messages
	ReceivedDiameterMessageFromPeer            BaseNodeEventMessageType = 2
	SuccessfullyDeliveredDiameterMessageToPeer BaseNodeEventMessageType = 3
	PeerSentDisconnectRequest                  BaseNodeEventMessageType = 4
	PeerFullyDisconnected                      BaseNodeEventMessageType = 5
	ReceivedCapabilitiesExchangeRequest        BaseNodeEventMessageType = 6
	ReceivedWatchdogRequest                    BaseNodeEventMessageType = 7
	SentWatchdogResponse                       BaseNodeEventMessageType = 8
	TransportClosed                            BaseNodeEventMessageType = 9
)

// BaseNodeEventMessage is a message emitted from a BaseApplicationNode describing
// an event that has occured while it is in a Start, Disconnecting, or Failed state
type BaseNodeEventMessage struct {
	Type                  BaseNodeEventMessageType
	DiameterMessage       *Message
	ForPeer               *Peer
	Error                 error
	AdditionalInformation interface{}
}

// VendorSpecificApplicationIDType is the type used by the ID field of VendorSpecificApplicationID
type VendorSpecificApplicationIDType int

// The type for a VendorSpecificApplictionID
const (
	AuthApplicationID VendorSpecificApplicationIDType = 1
	AcctApplicationID VendorSpecificApplicationIDType = 2
)

// VendorSpecificApplicationID represents a Vendor-Specific-Application-Id.  The Type declares
// whether the ID value is an AuthApplicationID or an AcctApplicationID
type VendorSpecificApplicationID struct {
	VendorID uint32
	Type     VendorSpecificApplicationIDType
	ID       uint32
}

// BaseApplicationConnectionHandler is a generic connection manager for the Base Diameter Application.
type BaseApplicationConnectionHandler struct {
	connection       net.Conn
	capabilitiesInfo BaseCapabilities
}

// NewBaseApplicationConnectionHandler constructs a BaseApplicationConnectionHandler.  The caller must
// have already opened a socket connecting client and server.  The capabilities provides details
// used in a Capabilities Exchange.
func NewBaseApplicationConnectionHandler(connection net.Conn, capabilities BaseCapabilities) *BaseApplicationConnectionHandler {
	return &BaseApplicationConnectionHandler{connection: connection, capabilitiesInfo: capabilities}
}

// MessageFilter is the signature for a method used to filter incoming message, determining whether they should
// continue for processing
type MessageFilter func(*Message) bool

// StartAsClient instructs the Handler to send a Capabilities-Exchange-Request, including the constructor-provided
// BaseCapabilities and any additionalCapabilitiesAvps (in the same order they are provided).  It then waits for
// a Capabilities-Exchange-Response.  This is passed to the ceaFilter.  If the filter is not nil and returns false,
// the eventChannel raises CapabilitiesExchangeFailed, closes the transport, raises TransportClosed, then
// returns.  Events are raised on the BaseNodeEventMessage channel.  This is intended to run as a goroutine.  If the
// channel sends a FatalTransportError or TransportClosed (which will happen after a Disconnect exchange, and some
// errors, including: WatchdogTimeoutExceeded and CapabilitiesExchangeFailed), then the function raises TransportClosed,
// closes the transport, then returns (the goroutine exits).  Once running, send a periodic Device-Watchdog-Request,
// and wait for Device-Watchdog-Responses, if there are no messages from the remote end within the timeout period.  If a
// response is not received within the watchdog timeout period, WatchdogTimeoutExceeded is raised, the transport is closed,
// TransportClosed is raised, and the function returns.
func (handler *BaseApplicationConnectionHandler) StartAsClient(eventChannel chan<- *BaseNodeEventMessage, additionalCapabilitiesAvps []*AVP) {

}

// StartAsServer instructs the Handler to wait for a Capabilities-Exchange-Request.  The CER diameter.Message is passed to
// the filter function (if it is not nil).  If the filter returns false, a CapabilitiesExchangeFailed is raised on the
// eventChannel, the transport is closed, TransportClosed is raised, then the function returns.  If the filter is nil or
// return true, the handler sends a Capabilities-Exchange-Response, including the constructor-provided
// BaseCapabilities and any additionalCapabilitiesAvps (in the same order they are provided).  Events are raised on
// the BaseNodeEventMessage channel.  This is intended to run as a goroutine.  If the channel sends a FatalTransportError
// or TransportClosed (which will happen after a Disconnect exchange, and some errors, including: WatchdogTimeoutExceeded and
// CapabilitiesExchangeFailed), then the function raises TransportClosed, closes the transport, then returns (the goroutine exits).
// Watchdog is the same mechanism as StartAsClient, except that the watchdog requests are sent slightly slower.
func (handler *BaseApplicationConnectionHandler) StartAsServer(eventChannel chan<- *BaseNodeEventMessage, additionalCapabilitiesAvps []*AVP, cerFilter MessageFilter) {

}
