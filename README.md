# golang Diameter

## Creating and using a Dictionary

A dictionary defines AVP code and type information, as well as message types and their corresponding codes.  A set of standard dictionaries are available in the dictionaries/ directory.

```yaml
AvpTypes:
    - Name: "Auth-Application-Id"
      Code: 258
      Type: "Unsigned32"
    - Name: "Auth-Request-Type"
      Code: 274
      Type: "Enumerated"
      Enumeration:
        - Name: "AUTHENTICATE_ONLY"
          Value: 1
        - Name: "AUTHORIZE_ONLY"
          Value: 2
        - Name: "AUTHORIZE_AUTHENTICATE"
          Value: 3
    - Name: "Acct-Session-Id"
      Code: 44
      Type: "OctetString"
    - Name: "Accounting-Sub-Session-Id"
      Code: 287
      Type: "Unsigned64"
    - Name: "Error-Message"
      Code: 281
      Type: "UTF8String"
    - Name: "Error-Reporting-Host"
      Code: 294
      Type: "DiamIdent"
    - Name: "Experimental-Result"
      Code: 297
      Type: "Grouped"
    - Name: "Host-IP-AddressInband-Security"
      Code: 257
      Type: "Address"
    - Name: "Redirect-Host"
      Code: 292
      Type: "DiamURI"
MessageTypes:
    - Basename: "Accouting"
      Abbreviations:
          Request: "ACR"
          Answer: "ACA"
      Code: 271
    - Basename: "Capabilities-Exchange"
      Abbreviations:
          Request: "CER"
          Answer: "CEA"
      Code: 257
    - Basename: "Device-Watchdog"
      Abbreviations:
          Request: "DWR"
          Answer: "DWA"
      Code: 280
    - Basename: "Disconnect-Peer"
      Abbreviations:
          Request: "DPR"
          Answer: "DPA"
      Code: 282
    - Basename: "Provide-Location"
      Abbreviations:
        Request: "PLR"
        Answer: "PLA"
      Code: 8388620
      Application-Id: 16777255
```

To load and use a dictionary:

```golang
    d := diameter.dictionary.FromYamlFile( yaml_dictionary_file_path )
    avp := AVP("Auth-Application-Id", uint32(0))

```

To use a dictionary:

```golang

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
