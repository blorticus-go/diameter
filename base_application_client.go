package diameter

// import "net"

// // BaseApplicationClient implements RFC 6733 Diameter Client mechanics
// type BaseApplicationClient struct {
// 	capabilities BaseCapabilities
// }

// // NewBaseApplicationClientErrorable creates a new BaseApplicationClient instance, using the provided
// // BaseCapabilities value.  An error is returned if any of the BaseCapabilities values are
// // invalid
// func NewBaseApplicationClientErrorable(capabilities BaseCapabilities) (*BaseApplicationClient, error) {
// 	return &BaseApplicationClient{capabilities: capabilities}, nil
// }

// // NewBaseApplicationClient is the same as NewBaseApplicationClientErrorable, except that this
// // method panics on an error.  This form allows chaining with other calls, but shifts the burden
// // of value checking on the caller.
// func NewBaseApplicationClient(capabilities BaseCapabilities) *BaseApplicationClient {
// 	baseApplication, err := NewBaseApplicationClientErrorable(capabilities)

// 	if err != nil {
// 		panic(err)
// 	}

// 	return baseApplication
// }

// // SetAuthApplicationIDs sets the optional Auth-Application-Id AVPs for Capabilities Exchanges
// func (client *BaseApplicationClient) SetAuthApplicationIDs(authApplicationIDs []uint32) *BaseApplicationClient {
// 	return client
// }

// // SetAcctApplicationIDs sets the optional Acct-Application-Id AVPs for Capabilities Exchanges
// func (client *BaseApplicationClient) SetAcctApplicationIDs(acctApplicationIDs []uint32) *BaseApplicationClient {
// 	return client
// }

// // AddSupportedVendorSpecificApplicationIDs sets the optional  AVP for Capabilities Exchanges
// func (client *BaseApplicationClient) AddSupportedVendorSpecificApplicationIDs(vendorSpecificAppIDs []VendorSpecificApplicationID) *BaseApplicationClient {
// 	return client
// }

// // Start starts the listen/send loop for this client instance.  It will periodically send Watchdog Request
// // messages to each of its connected peers, establish outbound connections and capabilities exchanges
// // when requested, send and receive Diameter messages, and raise errors.  The provided channel is used
// // to communicate with the caller based on events raised.  This is intended to run as a goroutine, and
// // should be started before attempting any peer connections.
// func (client *BaseApplicationClient) Start(<-chan *BaseNodeEventMessage) {

// }

// // ConnectToServer signals that the client should attempt to connect to the Diameter server identified by its
// // IP and port.  This is an asynchronous event.  If the connect fails, a RecoverableTransportError will be raised.
// // If the capabilities exchange fails, CapabilitiesExchangeFailed will be returned.  In both of those cases, the
// // corresponding BaseClientEventMessage will set both ForPeer (with the information for the peer to which this
// // connection was attempted) and Error.  On success, CapabilitiesExchangeSuccessfullyCompleted will be raised,
// // with ForPeer set.
// func (client *BaseApplicationClient) ConnectToServer(remoteIPAddress *net.IPAddr, remotePort uint32) {

// }

// // ActivePeers returns a list of the Peers that are currently in a connected state
// func (client *BaseApplicationClient) ActivePeers() []*Peer {
// 	return nil
// }

// // DisconnectFromPeer triggers a Disconnect-Peer-Request toward the identified peer, and on receipt of
// // Disconnect-Peer-Response, closes the transport.
// func (client *BaseApplicationClient) DisconnectFromPeer(peerToDisconnect *Peer) {

// }
