package entry

//import (
//	"errors"
//	"strings"
//
//	"crypto-conditions/ed25519sha256"
//	"crypto-conditions/sha256"
//	"crypto-conditions/thresholdSha256"
//)

//
//type Condition interface {
//}
//
////Interface Layer abstracting over
//type Fullfillment interface {
//	Serialize() string
//	Fullfill(Condition) bool
//}
//
//func ParseFullfillment(ful string) (*Fullfillment, error) {
//
//	parts := strings.Split(ful, ":")
//	if len(parts) != 4 {
//		return nil, errors.New("parsing error")
//	}
//
//	if parts[0] != "cf" {
//		return nil, errors.New("fulfillments must start with \"cf\"")
//	}
//
//	if parts[1] != "1" {
//		return nil, errors.New("must be protocol version 1")
//	}
//
//	var fullfill *Fullfillment
//	var err error
//	switch parts[2] {
//	case "1":
//		fullfill, err = Sha256.ParseFulfillment(ful)
//		return fullfill, err
//	case "2":
//		fullfill, err = Ed25519Sha256.ParseFulfillment(ful)
//		return fullfill, err
//	case "4":
//		fullfill, err = ThresholdSha256.ParseFulfillment(ful)
//		return fullfill, err
//	default:
//		return nil, errors.New("unsupported condition type")
//	}
//}
//
//func FulfillmentToCondition(ful string) (string, error) {
//	parts := strings.Split(ful, ":")
//	if len(parts) != 4 {
//		return "", errors.New("parsing error")
//	}
//
//	if parts[0] != "cf" {
//		return "", errors.New("fulfillments must start with \"cf\"")
//	}
//
//	if parts[1] != "1" {
//		return "", errors.New("must be protocol version 1")
//	}
//
//	switch parts[2] {
//	case "1":
//		return Sha256.FulfillmentToCondition(ful)
//	case "2":
//		return Ed25519Sha256.FulfillmentToCondition(ful)
//	case "4":
//		return ThresholdSha256.FulfillmentToCondition(ful)
//	default:
//		return "", errors.New("unsupported condition type")
//	}
//}
