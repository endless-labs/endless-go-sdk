package endless

import (
	"github.com/endless-labs/endless-go-sdk/bcs"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRawTransactionSign(t *testing.T) {
	sender, err := NewEd25519Account()
	assert.NoError(t, err)

	receiver, err := NewEd25519Account()
	assert.NoError(t, err)

	sn := uint64(1)
	amount := uint64(10_000)

	payload, err := CoinTransferPayload(nil, receiver.Address, amount)
	assert.NoError(t, err)

	txn := RawTransaction{
		Sender:                     sender.Address,
		SequenceNumber:             sn + 1,
		Payload:                    TransactionPayload{Payload: payload},
		MaxGasAmount:               1000,
		GasUnitPrice:               2000,
		ExpirationTimestampSeconds: 1714158778,
		ChainId:                    221,
	}

	signedTxn, err := txn.SignedTransaction(sender)
	assert.NoError(t, err)

	_, ok := signedTxn.Authenticator.Auth.(*Ed25519TransactionAuthenticator)
	assert.True(t, ok)

	assert.NoError(t, signedTxn.Verify())

	// Serialize, Deserialize, Serialize
	// out1 and out3 should be the same
	txn1Bytes, err := bcs.Serialize(&txn)
	assert.NoError(t, err)

	txn2 := RawTransaction{}
	err = bcs.Deserialize(&txn2, txn1Bytes)
	assert.NoError(t, err)

	txn2Bytes, err := bcs.Serialize(&txn2)
	assert.NoError(t, err)
	assert.Equal(t, txn1Bytes, txn2Bytes)
	assert.Equal(t, txn, txn2)
}

func TestTPMarshal(t *testing.T) {
	var wat TransactionPayload
	var ser bcs.Serializer
	wat.MarshalBCS(&ser)
	// without a payload, it should fail
	assert.Error(t, ser.Error())
}
