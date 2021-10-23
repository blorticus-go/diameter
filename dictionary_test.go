package diameter_test

import (
	"fmt"
	"testing"

	diameter "github.com/blorticus/go-diameter"
)

type dictionaryMessageTestCase struct {
	nameProvidedToDictionaryLookup string
	expectAnError                  bool
	expectedMessageCode            diameter.Uint24
	expectedMessageAppID           uint32
	expectMessageToBeRequest       bool
}

func (testCase *dictionaryMessageTestCase) AttemptUsingDictionary(dictionary *diameter.Dictionary) error {
	m, err := dictionary.MessageErrorable(testCase.nameProvidedToDictionaryLookup, diameter.MessageFlags{}, []*diameter.AVP{}, []*diameter.AVP{})
	if err != nil {
		if !testCase.expectAnError {
			return fmt.Errorf("did not expect error, got error = (%s)", err.Error())
		}
	} else {
		if testCase.expectAnError {
			return fmt.Errorf("expected error, got none")
		}
	}

	if !testCase.expectAnError {
		if m == nil {
			return fmt.Errorf("expected message, got nil")
		}
		if m.AppID != testCase.expectedMessageAppID {
			return fmt.Errorf("expected AppId = (%d), got = (%d)", testCase.expectedMessageAppID, m.AppID)
		}
		if m.Code != testCase.expectedMessageCode {
			return fmt.Errorf("expected Code = (%d), got = (%d)", testCase.expectedMessageCode, m.Code)
		}
		if testCase.expectMessageToBeRequest {
			if !m.IsRequest() {
				return fmt.Errorf("expect message to be a request, but it is not")
			}
		} else {
			if m.IsRequest() {
				return fmt.Errorf("expect message to be an answer, but it is not")
			}
		}
	}

	return nil
}

type avpTestCase struct {
	nameProvidedToDictionaryLookup string
	avpValue                       interface{}
	expectAnError                  bool
	expectedAvpCode                uint32
	expectedAvpVendorID            uint32
}

func (testCase *avpTestCase) AttemptUsingDictionary(dictionary *diameter.Dictionary) error {
	avp, err := dictionary.AVPErrorable(testCase.nameProvidedToDictionaryLookup, testCase.avpValue)

	if testCase.expectAnError {
		if err != nil {
			return nil
		}

		return fmt.Errorf("expected an error, got none")
	} else if err != nil {
		return fmt.Errorf("expected no error, got error = (%s)", err.Error())
	}

	if avp.Code != testCase.expectedAvpCode {
		return fmt.Errorf("expected code = (%d), got = (%d)", testCase.expectedAvpCode, avp.Code)
	}

	if avp.VendorID != testCase.expectedAvpVendorID {
		return fmt.Errorf("expected vendorId = (%d), got = (%d)", testCase.expectedAvpCode, avp.VendorID)
	}

	return nil
}

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
    - Name: "Globally-Unique-Address"
      Code: 300
      Vendor-Id: 13019
      Type: "Unsigned64"
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
    - Basename: "Update-Location"
      Abbreviations:
          Request: "ULR"
          Answer: "ULA"
      Code: 316
      Application-Id: 16777251
    - Basename: "Cancel-Location"
      Abbreviations:
          Request: "CLR"
          Answer: "CLA"
      Code: 317
      Application-Id: 16777251
`
	messageTestCases := []*dictionaryMessageTestCase{
		{
			nameProvidedToDictionaryLookup: "Accouting-Request",
			expectedMessageCode:            271,
			expectedMessageAppID:           0,
			expectMessageToBeRequest:       true,
		},
		{
			nameProvidedToDictionaryLookup: "Accouting-Answer",
			expectedMessageCode:            271,
			expectedMessageAppID:           0,
			expectMessageToBeRequest:       false,
		},
		{
			nameProvidedToDictionaryLookup: "CER",
			expectedMessageCode:            257,
			expectedMessageAppID:           0,
			expectMessageToBeRequest:       true,
		},
		{
			nameProvidedToDictionaryLookup: "CEA",
			expectedMessageCode:            257,
			expectedMessageAppID:           0,
			expectMessageToBeRequest:       false,
		},
		{
			nameProvidedToDictionaryLookup: "Update-Location-Request",
			expectedMessageCode:            316,
			expectedMessageAppID:           16777251,
			expectMessageToBeRequest:       true,
		},
		{
			nameProvidedToDictionaryLookup: "Update-Location-Answer",
			expectedMessageCode:            316,
			expectedMessageAppID:           16777251,
			expectMessageToBeRequest:       false,
		},
	}

	avpTestCases := []*avpTestCase{
		{
			nameProvidedToDictionaryLookup: "Auth-Application-Id",
			avpValue:                       uint32(10),
			expectedAvpCode:                258,
			expectedAvpVendorID:            0,
		},
		{
			nameProvidedToDictionaryLookup: "Globally-Unique-Address",
			avpValue:                       uint64(10),
			expectedAvpCode:                300,
			expectedAvpVendorID:            13019,
		},
	}

	dictionary, err := diameter.DictionaryFromYamlString(properBaseDiameterApplictionYamlString)

	if err != nil {
		t.Errorf("Error on DictionaryFromYamlString(): %s", err)
	} else {
		for indexForTestCase, testCase := range messageTestCases {
			if err := testCase.AttemptUsingDictionary(dictionary); err != nil {
				t.Errorf("(TestDictionaryValidValues) (Message test number %d) %s", indexForTestCase+1, err.Error())
			}
		}

		for indexForTestCase, testCase := range avpTestCases {
			if err := testCase.AttemptUsingDictionary(dictionary); err != nil {
				t.Errorf("(TestDictionaryValidValues) (AVP test number %d) %s", indexForTestCase+1, err.Error())
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

	dictionary, err := diameter.DictionaryFromYamlString(ValidDefinition)

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

	dictionary, err = diameter.DictionaryFromYamlString(InvalidDefinition)

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

	dictionary, err = diameter.DictionaryFromYamlString(InvalidDefinition)

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

	dictionary, err = diameter.DictionaryFromYamlString(InvalidDefinition)

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

	_, err := diameter.DictionaryFromYamlString(InvalidDefintion)

	if err == nil {
		t.Errorf("Expected error when AvpType.Type = Unsigned32, but no error")
	}
}
