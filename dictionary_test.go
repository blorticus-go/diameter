package diameter

import (
	"testing"
)

func TestBaseProtocolDefinitionFromString(t *testing.T) {
	properBaseDiameterApplictionYamlString := `---
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
`

	dictionary, err := FromYamlString(properBaseDiameterApplictionYamlString)

	if err != nil {
		t.Errorf("Error on FromYamlString(): %s", err)
	} else {
		avp, err := dictionary.AvpErrorable("Auth-Application-Id", uint32(10))

		if err != nil {
			t.Errorf("Error on dictionary.AVPErrorable('Auth-Application-Id', 10): %s", err)
		} else {
			if avp.Code != 258 {
				t.Errorf("avp code should be 258, is %d", avp.Code)
			}
		}
	}
}

func TestBasicYamlTypeErrors(t *testing.T) {
	// start by testing that a base definition is otherwise legal
	ValidDefinition := `---
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
`

	dictionary, err := FromYamlString(ValidDefinition)

	if err != nil {
		t.Errorf("On test of base ValidDefinition, expected no error, but got error = (%s)", err)
	} else if dictionary == nil {
		t.Errorf("On test of base ValidDefinition, expected non nil dictionary, but it is nil")
	}

	// Now run permutations of that ValidDefinition
	InvalidDefinition := `---
AvpTypes:
    - Name: "Auth-Application-Id"
      Code: 258
      Type: "Unsigned34"
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
`

	dictionary, err = FromYamlString(InvalidDefinition)

	if err == nil {
		t.Errorf("Expected error when AvpType.Type = Unsigned32 on first AVP, but got no error")
	}

	InvalidDefinition = `---
AvpTypes:
    - Name: "Auth-Application-Id"
      Code: 258
      Type: "Unsigned32"
    - Name: "Auth-Request-Type"
      Code: -1
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
`

	dictionary, err = FromYamlString(InvalidDefinition)

	if err == nil {
		t.Errorf("Expected error when AvpType.Code = -1 on second AVP, but got no error")
	}

	InvalidDefinition = `---
AvpTypes:
    - Name: "Auth-Application-Id"
      Code: 258
      Type: "Unsigned32"
    - Name: "Auth-Request-Type"
      Code: 274
      Type: "Enumerated"
      Enumeration:
        - Name: "AUTHENTICATE_ONLY"
          Value: "foo"
        - Name: "AUTHORIZE_ONLY"
          Value: 2
        - Name: "AUTHORIZE_AUTHENTICATE"
          Value: 3
    - Name: "Acct-Session-Id"
      Code: 44
      Type: "OctetString"
`

	dictionary, err = FromYamlString(InvalidDefinition)

	if err == nil {
		t.Errorf("Expected error when Enumveration.Value is a string on second AVP, but got no error")
	}
}

func TestInvalidYamlCode(t *testing.T) {
	InvalidDefintion := `---
AvpTypes:
    - Name: "Auth-Application-Id"
      Code: 258
      Type: "Unsigned32"
    - Name: "Auth-Request-Type"
      Code: -1
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
`

	_, err := FromYamlString(InvalidDefintion)

	if err == nil {
		t.Errorf("Expected error when AvpType.Type = Unsigned32, but no error")
	}
}
