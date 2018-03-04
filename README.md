## Use Case Examples

### Emulate Gx callflow (PCRF and PCEF).  Includes CCR/A PCEF->PCRF and RAR/A PCRF->PCEF

  
### Example

    d := diameter.dictionary.FromYamlFile( yaml_dictionary_file_path )

    i := diameter.NewInstance( origin_host, origin_realm )
    i.UseCallbacks( ... ) // start goroutine; each callback in a separate goroutine

    i.StartListening( bind_addr, bind_port )
    p := i.ConnectToPeer( remote_addr, remote_port )
    p.SendMessage( d.Message( "SLR", [d.Avp( "Origin-Host", ... ), ...] ) )

    for {
        msg := i.HandlerChannel

        if msg.type == PEER_CONNECTED ...
        if msg.type == PEER_CONNECTION_TERMINATED ...
        if msg.type == MESSAGE_FROM_PEER ...
        if msg.type == MESSAGE_DELIVERY_FAILURE ...
    }

    or using callbacks:
        PeerConnected( peer )
        PeerDisconnected( peer, reason )
        MessageReceived( message, from_peer )
        MessageDeliveryFailed( message, to_peer, reason )
