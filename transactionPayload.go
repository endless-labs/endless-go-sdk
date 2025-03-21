package endless

import (
	"errors"
	"fmt"
	"github.com/endless-labs/endless-go-sdk/bcs"
)

//region TransactionPayload

type TransactionPayloadVariant uint32

const (
	TransactionPayloadVariantScript        TransactionPayloadVariant = 0
	TransactionPayloadVariantModuleBundle  TransactionPayloadVariant = 1 // Deprecated
	TransactionPayloadVariantEntryFunction TransactionPayloadVariant = 2
	TransactionPayloadVariantMultisig      TransactionPayloadVariant = 3
	TransactionPayloadVariantSafeScript        TransactionPayloadVariant = 4
	TransactionPayloadVariantSafeEntryFunction TransactionPayloadVariant = 5
)

type TransactionPayloadImpl interface {
	bcs.Struct
	PayloadType() TransactionPayloadVariant // This is specifically to ensure that wrong types don't end up here
}

// TransactionPayload the actual instructions of which functions to call on chain
type TransactionPayload struct {
	Payload TransactionPayloadImpl
}

//region TransactionPayload bcs.Struct

func (txn *TransactionPayload) MarshalBCS(ser *bcs.Serializer) {
	if txn == nil || txn.Payload == nil {
		ser.SetError(fmt.Errorf("nil transaction payload"))
		return
	}
	ser.Uleb128(uint32(txn.Payload.PayloadType()))
	txn.Payload.MarshalBCS(ser)
}
func (txn *TransactionPayload) UnmarshalBCS(des *bcs.Deserializer) {
	payloadType := TransactionPayloadVariant(des.Uleb128())

	switch payloadType {
	case TransactionPayloadVariantScript:
		txn.Payload = &Script{}
	case TransactionPayloadVariantModuleBundle:
		// Deprecated, should never be in production
		des.SetError(fmt.Errorf("module bundle is not supported as a transaction payload"))
		return
	case TransactionPayloadVariantEntryFunction:
		txn.Payload = &EntryFunction{}
	case TransactionPayloadVariantMultisig:
		txn.Payload = &Multisig{}
	default:
		des.SetError(fmt.Errorf("bad txn payload kind, %d", payloadType))
		return
	}

	txn.Payload.UnmarshalBCS(des)
}

//endregion
//endregion

//region ModuleBundle

// ModuleBundle is long deprecated and no longer used, but exist as an enum position in TransactionPayload
type ModuleBundle struct{}

func (txn *ModuleBundle) PayloadType() TransactionPayloadVariant {
	return TransactionPayloadVariantModuleBundle
}

func (txn *ModuleBundle) MarshalBCS(ser *bcs.Serializer) {
	ser.SetError(errors.New("ModuleBundle unimplemented"))
}
func (txn *ModuleBundle) UnmarshalBCS(des *bcs.Deserializer) {
	des.SetError(errors.New("ModuleBundle unimplemented"))
}

//endregion ModuleBundle

//region EntryFunction

// EntryFunction call a single published entry function arguments are ordered BCS encoded bytes
type EntryFunction struct {
	Module   ModuleId
	Function string
	ArgTypes []TypeTag
	Args     [][]byte
}

//region EntryFunction TransactionPayloadImpl

func (sf *EntryFunction) PayloadType() TransactionPayloadVariant {
	return TransactionPayloadVariantEntryFunction
}

//endregion

//region EntryFunction bcs.Struct

func (sf *EntryFunction) MarshalBCS(ser *bcs.Serializer) {
	sf.Module.MarshalBCS(ser)
	ser.WriteString(sf.Function)
	bcs.SerializeSequence(sf.ArgTypes, ser)
	ser.Uleb128(uint32(len(sf.Args)))
	for _, a := range sf.Args {
		ser.WriteBytes(a)
	}
}
func (sf *EntryFunction) UnmarshalBCS(des *bcs.Deserializer) {
	sf.Module.UnmarshalBCS(des)
	sf.Function = des.ReadString()
	sf.ArgTypes = bcs.DeserializeSequence[TypeTag](des)
	alen := des.Uleb128()
	sf.Args = make([][]byte, alen)
	for i := range alen {
		sf.Args[i] = des.ReadBytes()
	}
}

//endregion
//endregion

type SafeEntryFunction struct {
	Module   ModuleId
	Function string
	ArgTypes []TypeTag
	Args     [][]byte
	Hash     [32]byte
}

func (sf *SafeEntryFunction) PayloadType() TransactionPayloadVariant {
	return TransactionPayloadVariantSafeEntryFunction
}

func (sf *SafeEntryFunction) MarshalBCS(ser *bcs.Serializer) {
	sf.Module.MarshalBCS(ser)
	ser.WriteString(sf.Function)
	bcs.SerializeSequence(sf.ArgTypes, ser)
	ser.Uleb128(uint32(len(sf.Args)))
	for _, a := range sf.Args {
		ser.WriteBytes(a)
	}
	ser.FixedBytes(sf.Hash[:])
}
func (sf *SafeEntryFunction) UnmarshalBCS(des *bcs.Deserializer) {
	sf.Module.UnmarshalBCS(des)
	sf.Function = des.ReadString()
	sf.ArgTypes = bcs.DeserializeSequence[TypeTag](des)
	alen := des.Uleb128()
	sf.Args = make([][]byte, alen)
	for i := range alen {
		sf.Args[i] = des.ReadBytes()
	}
	for i, value := range des.ReadBytes() {
		sf.Hash[i] = value
	}
}

//region Multisig

// Multisig is an on-chain multisig transaction, that calls an entry function associated
type Multisig struct {
	MultisigAddress AccountAddress
	Payload         *MultisigTransactionPayload // Optional
}

//region Multisig TransactionPayloadImpl

func (sf *Multisig) PayloadType() TransactionPayloadVariant {
	return TransactionPayloadVariantMultisig
}

//endregion

//region Multisig bcs.Struct

func (sf *Multisig) MarshalBCS(ser *bcs.Serializer) {
	ser.Struct(&sf.MultisigAddress)

	if sf.Payload == nil {
		ser.Bool(false)
	} else {
		ser.Bool(true)
		ser.Struct(sf.Payload)
	}
}
func (sf *Multisig) UnmarshalBCS(des *bcs.Deserializer) {
	des.Struct(&sf.MultisigAddress)
	if des.Bool() {
		sf.Payload = &MultisigTransactionPayload{}
		des.Struct(sf.Payload)
	}
}

//endregion
//endregion

//region MultisigTransactionPayload

type MultisigTransactionPayloadVariant uint32

const (
	MultisigTransactionPayloadVariantEntryFunction MultisigTransactionPayloadVariant = 0
)

type MultisigTransactionImpl interface {
	bcs.Struct
}

// MultisigTransactionPayload is an enum allowing for multiple types of transactions to be called via multisig
//
// Note this does not implement TransactionPayloadImpl
type MultisigTransactionPayload struct {
	Variant MultisigTransactionPayloadVariant
	Payload MultisigTransactionImpl
}

//region MultisigTransactionPayload bcs.Struct

func (sf *MultisigTransactionPayload) MarshalBCS(ser *bcs.Serializer) {
	ser.Uleb128(uint32(sf.Variant))
	ser.Struct(sf.Payload)
}
func (sf *MultisigTransactionPayload) UnmarshalBCS(des *bcs.Deserializer) {
	variant := MultisigTransactionPayloadVariant(des.Uleb128())
	switch variant {
	case MultisigTransactionPayloadVariantEntryFunction:
		sf.Payload = &EntryFunction{}
	default:
		des.SetError(fmt.Errorf("bad variant %d for MultisigTransactionPayload", variant))
		return
	}
	des.Struct(sf.Payload)
}

//endregion
//endregion
