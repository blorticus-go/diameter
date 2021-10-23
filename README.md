# golang Diameter

## Use Case Examples

### Emulate Gx callflow (PCRF and PCEF).  Includes CCR/A PCEF->PCRF and RAR/A PCRF->PCEF

### Examples

## Creating and using a Dictionary

```golang
    d := diameter.dictionary.FromYamlFile( yaml_dictionary_file_path )
```

## Base Application Server

```golang
    server := NewBaseApplicationServer(BaseCapabilities{OriginHost: "host", OriginRealm: "realm", ...}).
        SetAuthApplicationIDs(uint32[]{1, 2, 3}).
        SetIncomingTransportFilter(transportFilterFunction).
        SetIncomingCapabilitiesExchangeFilter(cerFilterFunction)
    serverEventChan := make(chan *BaseNodeEventMessage)
    server.Start(serverEventChan)

    for {
        switch event := <-serverEventChan; event.Type {
        case IncomingTransportAttemptBlocked:
            // ...

        case IncomingPeerBlockedOnCapbilitiesExchange:
            // ...

        case CapabilitiesExchangeSuccessfullyCompleted:
            // ...

        // ... etc ...
        }
    }
```

## Base Application Client

```golang
    client := NewBaseApplicationClient(BaseCapabilities{OriginHost: "host", OriginRealm: "realm", ...}).
        SetAuthApplicationIDs(uint32[]{1, 2, 3}).
        SetIncomingTransportFilter(transportFilterFunction).
        SetIncomingCapabilitiesExchangeFilter(cerFilterFunction)
    clientEventChan := make(chan *BaseNodeEventMessage)
    client.Start(clientEventChan)

    for {
        select {
            case event := <-clientEventChan:
                switch event.Type {
                    // ...
                }

            default:
                if someConditionIsTrue {
                    client.ConnectToServer(...)
                }
        }
    }
```
