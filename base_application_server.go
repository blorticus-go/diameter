package diameter

// import (
// 	"fmt"
// 	"net"
// )

// // BaseApplicationServer implements RFC 6733 Diameter Server mechanics
// type BaseApplicationServer struct {
// 	baseApplicationCapabilities BaseCapabilities
// 	currentActiveListenerCount  uint
// }

// // NewBaseApplicationServerErrorable creates a new BaseApplicationServer instance, using the provided
// // BaseCapabilities value.  The set of listeners are already opened, listen sockets.  An error is
// // returned if any of the BaseCapabilities values are invalid
// func NewBaseApplicationServerErrorable(capabilities BaseCapabilities) (*BaseApplicationServer, error) {
// 	server := &BaseApplicationServer{
// 		baseApplicationCapabilities: capabilities,
// 		currentActiveListenerCount:  0,
// 	}

// 	return server, nil
// }

// // NewBaseApplicationServer is the same as NewBaseApplicationClientErrorable, except that this
// // method panics on an error.  This form allows chaining with other calls, but shifts the burden
// // of value checking on the caller.
// func NewBaseApplicationServer(capabilities BaseCapabilities) *BaseApplicationServer {
// 	baseApplication, err := NewBaseApplicationServerErrorable(capabilities)

// 	if err != nil {
// 		panic(err)
// 	}

// 	return baseApplication
// }

// // SetAuthApplicationIDs sets the optional Auth-Application-Id AVPs for Capabilities Exchanges
// func (server *BaseApplicationServer) SetAuthApplicationIDs(authApplicationIDs []uint32) *BaseApplicationServer {
// 	return server
// }

// // SetAcctApplicationIDs sets the optional Acct-Application-Id AVPs for Capabilities Exchanges
// func (server *BaseApplicationServer) SetAcctApplicationIDs(acctApplicationIDs []uint32) *BaseApplicationServer {
// 	return server
// }

// // AddSupportedVendorSpecificApplicationIDs sets the optional  AVP for Capabilities Exchanges
// func (server *BaseApplicationServer) AddSupportedVendorSpecificApplicationIDs(vendorSpecificAppIDs []VendorSpecificApplicationID) *BaseApplicationServer {
// 	return server
// }

// // used by anonymous go routine in server.Start
// type messageFromListener struct {
// 	sourceOfMessage            net.Addr
// 	fatalError                 error
// 	receivedIncomingConnection net.Conn
// }

// // Start starts the listen/send loop for this server instance.  It will periodically send Watchdog Request
// // messages to each of its connected peers, receive connections and capabilities exchanges
// // when requested, send and receive Diameter messages, and raise errors.  The provided channel is used
// // to communicate with the caller based on events raised.  This is intended to run as a goroutine.
// func (server *BaseApplicationServer) Start(initialListeners []net.Listener, eventMessageChannel chan<- *BaseNodeEventMessage) {
// 	if initialListeners == nil || len(initialListeners) < 1 {
// 		return
// 	}

// 	listenerMessagesChannel := make(chan *messageFromListener, 10)

// 	for _, listener := range initialListeners {
// 		go func(listener net.Listener, messageChannel chan<- *messageFromListener) {
// 			for {
// 				conn, err := listener.Accept()

// 				if err != nil {
// 					messageChannel <- &messageFromListener{sourceOfMessage: listener.Addr(), fatalError: err, receivedIncomingConnection: nil}
// 					return
// 				}

// 				messageChannel <- &messageFromListener{sourceOfMessage: listener.Addr(), fatalError: nil, receivedIncomingConnection: conn}
// 			}
// 		}(listener, listenerMessagesChannel)
// 	}

// 	activeListenerCount := len(initialListeners)

// 	for {
// 		select {
// 		case incomingListenerMessage := <-listenerMessagesChannel:
// 			if incomingListenerMessage.fatalError != nil {
// 				eventMessageChannel <- &BaseNodeEventMessage{
// 					Type:                  ListenerFailed,
// 					Error:                 incomingListenerMessage.fatalError,
// 					AdditionalInformation: incomingListenerMessage.sourceOfMessage,
// 				}

// 				activeListenerCount--
// 				if activeListenerCount < 1 {
// 					eventMessageChannel <- &BaseNodeEventMessage{
// 						Type:  AllListenersHaveFailed,
// 						Error: fmt.Errorf("All Listeners Have Failed"),
// 					}

// 					return
// 				}
// 			} else {
// 				handlerForPeerConnection := NewBaseApplicationConnectionHandler(
// 					incomingListenerMessage.receivedIncomingConnection,
// 					server.baseApplicationCapabilities,
// 				)

// 				// TODO: add extra AVPs if they are defined in server construction
// 				go handlerForPeerConnection.StartAsServer(eventMessageChannel, []*AVP{}, nil)
// 			}
// 		}
// 	}
// }

// // ActivePeers returns a list of the Peers that are currently in a connected state
// func (server *BaseApplicationServer) ActivePeers() []*Peer {
// 	return nil
// }

// // DisconnectFromPeer triggers a Disconnect-Peer-Request toward the identified peer, and on receipt of
// // Disconnect-Peer-Response, closes the transport.
// func (server *BaseApplicationServer) DisconnectFromPeer(peerToDisconnect *Peer) {

// }
