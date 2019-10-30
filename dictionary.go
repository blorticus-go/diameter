package diameter

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// import (
// 	"fmt"
// 	"io/ioutil"
// 	//	"utils"
// )
//
// Dictionary represents a dictionary of AVP definitions
type Dictionary struct {
	// 	avps                  map[string]*AVPAttributes
	// 	msgs                  map[string]*MessageAttributes // indexed both by Name and Abbrev
	// 	panicOnLookupFailures bool
}

//
// func check_error(e error) {
// 	if e != nil {
// 		panic(e)
// 	}
// }
//
// ReadYamlDictionaryFile reads a YAML file in the proscribed YAML
// format for an AVP dictionary
func ReadYamlDictionaryFile(filename string) (*Dictionary, error) {
	self := Dictionary{
		avps: make(map[string]*AVPAttributes),
		msgs: make(map[string]*MessageAttributes),
		panicOnLookupFailures: false,
	}

	avpTypeMap := func() map[string]AVPAttributeType {
		out := make(map[string]AVPAttributeType)
		for i := Unsigned32; i <= Grouped; i++ {
			out[i.String()] = i
		}
		return out
	}()

	dat, err := ioutil.ReadFile(filename)
	utils.CheckError(err)

	m := make(map[interface{}]interface{})
	err = yaml.Unmarshal([]byte(dat), &m)
	utils.CheckError(err)

	avpm := utils.CheckMapList(m, "avps")

	for _, entry := range avpm {
		emap := entry.(map[interface{}]interface{})
		ename := emap["name"].(string)
		etype := avpTypeMap[emap["type"].(string)]
		evalues := make(map[uint32]string)

		if emap["values"] != nil {
			for _, value := range emap["values"].([]interface{}) {
				vmap := value.(map[interface{}]interface{})
				evalues[uint32(vmap["value"].(int))] = vmap["name"].(string)
			}
		}
		self.avps[ename] = NewAVPAttributeAndValue(ename,
			uint32(emap["code"].(int)),
			uint32(emap["vendorid"].(int)),
			etype, evalues)
	}

	msgm := utils.CheckMapList(m, "messages")
	for _, entry := range msgm {
		m_map := entry.(map[interface{}]interface{})
		m_avps := make([]*AVPAttribute, 0)
		if m_map["mandatory_avps"] != nil {
			for _, man := range m_map["mandatory_avps"].([]interface{}) {
				man_map := man.(map[interface{}]interface{})
				var avp *AVPAttribute
				if man_map["code"] != nil {
					avp = TypeToAVPAttribute[uint32(man_map["code"].(int))]
				} else if man_map["name"] != nil {
					avp = self.avps[man_map["name"].(string)]
				}
				if avp != nil {
					m_avp := avp.clone()
					if man_map["min"] != nil {
						m_avp.min = man_map["min"].(int)
					} else {
						m_avp.min = 1
					}
					if man_map["max"] != nil {
						m_avp.max = man_map["max"].(int)
					} else {
						m_avp.max = 1
					}
					m_avps = append(m_avps, m_avp)
				}
			}
		}
		msg_attr := NewMessageAttribute(m_map["name"].(string), m_map["abbreviation"].(string), Uint24(m_map["code"].(int)), m_map["is_request"].(bool), m_avps)
		self.msgs[msg_attr.msgName] = msg_attr
		self.msgs[msg_attr.msgAbbrv] = msg_attr
	}

	return &self, nil
}

// // AVP returns an AVP with the name 'avp_name' from the loaded dictionary, providing the
// // value 'typed_data'.  mandatory and protected flags are both set to false.
// func (self *Dictionary) AVP(avp_name string, typed_data interface{}) *AVP {
// 	return self.AVPWithFlags(avp_name, map[string]bool{"mandatory": false, "protected": false}, typed_data)
//
// }
//
// // PanicOnLookupFailures inidcates whether the Dictionary instance should panic() with a message
// // if a lookup method (e.g., MsgCode()) is provided lookup string is not in the dictionary,
// // or simply return a flag value
// func (dict *Dictionary) PanicOnLookupFailures(doso bool) {
// 	dict.panicOnLookupFailures = doso
// }
//
// // AVPWithFlags returns the same as AVP, but a map of the 'mandatory' and 'protected' flags
// // is also provided.
// func (self *Dictionary) AVPWithFlags(avp_name string, flags map[string]bool, typed_data interface{}) *AVP {
// 	avp := self.avps[avp_name]
// 	if avp == nil {
// 		panic(fmt.Errorf("Attribute not found %s", avp_name))
// 	}
// 	if flags == nil {
// 		flags = map[string]bool{}
// 	}
// 	mandatory, _ := flags["mandatory"]
// 	protected, _ := flags["protected"]
//
// 	return NewAVP(avp, mandatory, protected, nil, typed_data)
// }
//
// // MsgCode retrieves the Diameter message Code for a particular name (or abbreviation) in the dictionary.
// // Returns 0 if 'msg_code_name' is not in the dictionary, unless PanicOnLookupFailures is set,
// // in which case, panic() with message
// func (dict *Dictionary) MsgCode(msg_code_name string) Uint24 {
// 	if attr, exists := dict.msgs[msg_code_name]; exists {
// 		return attr.msgCode
// 	} else if dict.panicOnLookupFailures {
// 		panic(fmt.Sprintf("Message code with name [%s] is not in the dictionary", msg_code_name))
// 	} else {
// 		return 0
// 	}
// }
//
// // MsgAttributes retrieves the diameter.MessageAttributes associated with the 'msg_code_name' (which
// // may either be the proper name or the abbreviation).  Returns nil if the entry is not in the
// // dictionary, unless PanicOnLookupFailures is set, in which case, panic() with message.
// // Changes to the returned pointed datastructure will not alter the dictionary
// func (dict *Dictionary) MsgAttributes(msg_code_name string) *MessageAttributes {
// 	if val, exists := dict.msgs[msg_code_name]; exists {
// 		r := new(MessageAttributes)
// 		r = val
// 		return r
// 	} else if dict.panicOnLookupFailures {
// 		panic(fmt.Sprintf("No entry in dictionary for message named [%s]", msg_code_name))
// 	} else {
// 		return nil
// 	}
// }
//
// func (self *Dictionary) Message(msg_name string, ids map[string]uint32, mandatory []*AVP, additional []*AVP) *Message {
// 	msg_attr := self.msgs[msg_name]
// 	if msg_attr == nil {
// 		panic(fmt.Errorf("Message not found %s", msg_name))
// 	}
// 	if ids == nil {
// 		ids = map[string]uint32{}
// 	}
// 	flags := uint8(0x00)
// 	if msg_attr.msgIsRequest {
// 		flags &= MsgFlagRequest
// 	}
// 	appID, _ := ids["app"]
// 	hopByHopID, _ := ids["hopByHop"]
// 	endToEndID, _ := ids["endToEnd"]
// 	return NewMessage(flags, msg_attr.msgCode, appID, hopByHopID, endToEndID, mandatory, additional)
// }
