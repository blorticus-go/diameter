package diameter

import (
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v2"
)

// DictionaryYamlMetadataSpecificationType is the type for a dictionary yaml field Metadata section
type DictionaryYamlMetadataSpecificationType struct {
	Type       string `yaml:"Type"`
	Identifier string `yaml:"Identifier"`
	URL        string `yaml:"URL"`
}

// DictionaryYamlMetadataType is the type for a dictionary yaml Metadata section Specification subsection
type DictionaryYamlMetadataType struct {
	Name           string                                    `yaml:"Name"`
	Specifications []DictionaryYamlMetadataSpecificationType `yaml:"Specifications"`
}

// DictionaryYamlAvpEnumerationType is the type for Avp Enumerations
type DictionaryYamlAvpEnumerationType struct {
	Name  string `yaml:"Name"`
	Value uint32 `yaml:"Value"`
}

// DictionaryYamlAvpType is the type for AvpTypes in a Diameter YAML Dictionary
type DictionaryYamlAvpType struct {
	Name        string                             `yaml:"Name"`
	Code        uint32                             `yaml:"Code"`
	Type        string                             `yaml:"Type"`
	VendorID    uint32                             `yaml:"Vendor-Id"`
	Enumeration []DictionaryYamlAvpEnumerationType `yaml:"Enumeration"`
}

// DictionaryYamlMessageAbbreviation is the type for MessageTypes.Abbreviations in a Diameter YAML Dictionary
type DictionaryYamlMessageAbbreviation struct {
	Request string `yaml:"Request"`
	Answer  string `yaml:"Answer"`
}

// DictionaryYamlMessageType is the type for MessageTypes in a Diameter YAML Dictionary
type DictionaryYamlMessageType struct {
	Basename      string                            `yaml:"Basename"`
	Code          uint32                            `yaml:"Code"`
	ApplicationID uint32                            `yaml:"Application-Id"`
	Abbreviations DictionaryYamlMessageAbbreviation `yaml:"Abbreviations"`
}

// DictionaryYaml represents a YAML dictionary containing Diameter message type and AVP definitions
type DictionaryYaml struct {
	AvpTypes     []DictionaryYamlAvpType     `yaml:"AvpTypes"`
	MessageTypes []DictionaryYamlMessageType `yaml:"MessageTypes"`
}

type dictionaryMessageDescriptor struct {
	name          string
	code          uint32
	appID         uint32
	isRequestType bool
}

type dictionaryAvpDescriptor struct {
	name             string
	code             uint32
	isVendorSpecific bool
	vendorID         uint32
	dataType         AVPDataType
}

type avpFullyQualifiedCodeType struct {
	vendorID uint32
	code     uint32
}

// Dictionary is a Diameter dictionary, mapping AVP and message type data to names
type Dictionary struct {
	messageDescriptorByNameOrAbbreviation map[string]*dictionaryMessageDescriptor
	requestMessageDescriptorByCode        map[uint32]*dictionaryMessageDescriptor
	answerMessageDescriptorByCode         map[uint32]*dictionaryMessageDescriptor
	avpDescriptorByName                   map[string]*dictionaryAvpDescriptor
	avpDescriptorByFullyQualifiedCode     map[avpFullyQualifiedCodeType]*dictionaryAvpDescriptor
}

var mapOfYamlAvpTypeStringToAVPDataType = map[string]AVPDataType{
	"Unsigned32":  Unsigned32,
	"Unsigned64":  Unsigned64,
	"Integer32":   Integer32,
	"Integer64":   Integer64,
	"Enumerated":  Enumerated,
	"OctetString": OctetString,
	"UTF8String":  UTF8String,
	"Grouped":     Grouped,
	"Address":     Address,
	"Time":        Time,
	"DiamIdent":   DiamIdent,
	"DiamURI":     DiamURI,
}

func convertYamlAvpToDictionaryAvpDescriptor(yamlAvp *DictionaryYamlAvpType) (*dictionaryAvpDescriptor, error) {
	avpDescriptor := &dictionaryAvpDescriptor{
		code:     yamlAvp.Code,
		name:     yamlAvp.Name,
		vendorID: yamlAvp.VendorID,
	}

	if avpDataType, typeStringIsRecognized := mapOfYamlAvpTypeStringToAVPDataType[yamlAvp.Type]; typeStringIsRecognized {
		avpDescriptor.dataType = avpDataType
	} else {
		return nil, fmt.Errorf("Provided Type (%s) invalid", yamlAvp.Type)
	}

	if yamlAvp.VendorID != 0 {
		avpDescriptor.isVendorSpecific = true
	}

	return avpDescriptor, nil
}

// fromYamlForm converts a DictionaryYaml to a Dictionary.  Returns error if a failure occurs
// or the values in the DictionaryYaml are malformed.
func fromYamlForm(yamlForm *DictionaryYaml) (*Dictionary, error) {
	dictionary := Dictionary{
		messageDescriptorByNameOrAbbreviation: make(map[string]*dictionaryMessageDescriptor),
		requestMessageDescriptorByCode:        make(map[uint32]*dictionaryMessageDescriptor),
		answerMessageDescriptorByCode:         make(map[uint32]*dictionaryMessageDescriptor),
		avpDescriptorByName:                   make(map[string]*dictionaryAvpDescriptor),
		avpDescriptorByFullyQualifiedCode:     make(map[avpFullyQualifiedCodeType]*dictionaryAvpDescriptor),
	}

	for _, yamlAvpType := range yamlForm.AvpTypes {
		avpDescriptor, err := convertYamlAvpToDictionaryAvpDescriptor(&yamlAvpType)

		if err != nil {
			return nil, err
		}

		dictionary.avpDescriptorByName[yamlAvpType.Name] = avpDescriptor
		dictionary.avpDescriptorByFullyQualifiedCode[avpFullyQualifiedCodeType{code: yamlAvpType.Code, vendorID: yamlAvpType.VendorID}] = avpDescriptor
	}

	for _, yamlMessageType := range yamlForm.MessageTypes {
		messageDescriptor := &dictionaryMessageDescriptor{
			code:          yamlMessageType.Code,
			name:          yamlMessageType.Basename + "-Request",
			appID:         yamlMessageType.ApplicationID,
			isRequestType: true,
		}

		dictionary.messageDescriptorByNameOrAbbreviation[yamlMessageType.Basename+"-Request"] = messageDescriptor
		dictionary.messageDescriptorByNameOrAbbreviation[yamlMessageType.Abbreviations.Request] = messageDescriptor
		dictionary.requestMessageDescriptorByCode[yamlMessageType.Code] = messageDescriptor

		messageDescriptor = &dictionaryMessageDescriptor{
			code:          yamlMessageType.Code,
			name:          yamlMessageType.Basename + "-Answer",
			appID:         yamlMessageType.ApplicationID,
			isRequestType: false,
		}

		dictionary.messageDescriptorByNameOrAbbreviation[yamlMessageType.Basename+"-Answer"] = messageDescriptor
		dictionary.messageDescriptorByNameOrAbbreviation[yamlMessageType.Abbreviations.Answer] = messageDescriptor
		dictionary.answerMessageDescriptorByCode[yamlMessageType.Code] = messageDescriptor
	}

	return &dictionary, nil
}

// DictionaryFromYamlFile processes a file that should be a YAML formatted Diameter dictionary
func DictionaryFromYamlFile(filepath string) (*Dictionary, error) {
	contentsOfFileAsString, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file (%s): %s", filepath, err.Error())
	}

	return DictionaryFromYamlString(string(contentsOfFileAsString))
}

// DictionaryFromYamlString reads a string containing a Diameter dictionary in YAML format
func DictionaryFromYamlString(yamlString string) (*Dictionary, error) {
	dictionaryYaml := new(DictionaryYaml)
	err := yaml.Unmarshal([]byte(yamlString), &dictionaryYaml)

	if err != nil {
		return nil, err
	}

	dictionary, err := fromYamlForm(dictionaryYaml)

	if err != nil {
		return nil, err
	}

	return dictionary, nil

}

// DataTypeForAVPNamed looks up the data type for the specific AVP
func (dictionary *Dictionary) DataTypeForAVPNamed(name string) (AVPDataType, error) {
	descriptor, isInMap := dictionary.avpDescriptorByName[name]

	if !isInMap {
		return TypeOrAvpUnknown, fmt.Errorf("no AVP named (%s) in the dictionary", name)
	}

	return descriptor.dataType, nil
}

// AVPErrorable returns an AVP based on the dictionary definition.  If the name is not in
// the dictionary, or the value type is incorrect based on the dictionary definition,
// return an error.  This is Errorable because it may throw an error.  It is assumed
// that this will be the uncommon case, because ordinarily, the value will be known in
// advance by the application creating it.
func (dictionary *Dictionary) AVPErrorable(name string, value interface{}) (*AVP, error) {
	descriptor, isInMap := dictionary.avpDescriptorByName[name]

	if !isInMap {
		return nil, fmt.Errorf("no AVP named (%s) in the dictionary", name)
	}

	return NewTypedAVPErrorable(descriptor.code, descriptor.vendorID, false, descriptor.dataType, value)
}

// AVP is the same as AVPErrorable, except that, if an error occurs, panic() is invoked
// with the error string
func (dictionary *Dictionary) AVP(name string, value interface{}) *AVP {
	avp, err := dictionary.AVPErrorable(name, value)

	if err != nil {
		panic(err)
	}

	return avp
}

// MessageFlags provides the Diameter Message flag types
type MessageFlags struct {
	Proxiable           bool
	Error               bool
	PotentialRetransmit bool
}

// MessageErrorable returns a Message based on the dictionary definition.  If the name is
// not present in the dictionary, an error is returned.  The AVP set will be re-arranged to
// match the AVP order presented in the dictionary for the message type, and the mandatory
// flag will be changed to match the definition for the message type.  An error, however, is
// not raised if a mandatory flag is not present.
func (dictionary *Dictionary) MessageErrorable(name string, flags MessageFlags, mandatoryAVPs []*AVP, additionalAVPs []*AVP) (*Message, error) {
	messageDescriptor, messageTypeIsDefined := dictionary.messageDescriptorByNameOrAbbreviation[name]
	if !messageTypeIsDefined {
		return nil, fmt.Errorf("message of type (%s) is not known", name)
	}

	flagsEncoded := uint8(0)
	if flags.PotentialRetransmit {
		flagsEncoded |= MsgFlagPotentialRetransmit
	}
	if flags.Error {
		flagsEncoded |= MsgFlagError
	}
	if flags.Proxiable {
		flagsEncoded |= MsgFlagProxiable
	}

	if messageDescriptor.isRequestType {
		flagsEncoded |= MsgFlagRequest
	}

	return NewMessage(flagsEncoded, Uint24(messageDescriptor.code), messageDescriptor.appID, 0, 0, mandatoryAVPs, additionalAVPs), nil
}

// Message is the same as MessageErrorable, except that, if an error occurs, panic() is
// invoked with the error string
func (dictionary *Dictionary) Message(name string, flags MessageFlags, mandatoryAVPs []*AVP, additionalAVPs []*AVP) *Message {
	m, err := dictionary.MessageErrorable(name, flags, mandatoryAVPs, additionalAVPs)
	if err != nil {
		panic(err)
	}

	return m
}
