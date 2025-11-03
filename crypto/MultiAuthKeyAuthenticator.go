package crypto

import (
	"fmt"
	"github.com/endless-labs/endless-go-sdk/bcs"
)

type MultiAuthKeyAuthenticator struct {
	PubKeys    []*AnyPublicKey // The public key of the authenticator
	Signatures []*AnySignature // The signature of the authenticator
}

func (ea *MultiAuthKeyAuthenticator) PublicKey() PublicKey {
	return nil
}
func (ea *MultiAuthKeyAuthenticator) Signature() Signature {
	return nil
}
func (ea *MultiAuthKeyAuthenticator) Verify(msg []byte) bool {
	if len(ea.PubKeys) != len(ea.Signatures) {
		return false
	}

	for i := 0; i < len(ea.PubKeys); i++ {
		if !ea.PubKeys[i].Verify(msg, ea.Signatures[i].Signature) {
			return false
		}
	}
	return true
}
func (ea *MultiAuthKeyAuthenticator) FromAuthenticators(auths []*AccountAuthenticator) error {
	ea.PubKeys = make([]*AnyPublicKey, len(auths))
	ea.Signatures = make([]*AnySignature, len(auths))

	var err error
	for i := 0; i < len(auths); i++ {
		ea.PubKeys[i], ea.Signatures[i], err = fromAuthenticator(auths[i])
		if err != nil {
			return err
		}
	}

	return nil
}
func (ea *MultiAuthKeyAuthenticator) MarshalBCS(ser *bcs.Serializer) {
	bcs.SerializeSequence(ea.PubKeys, ser)
	bcs.SerializeSequence(ea.Signatures, ser)
}
func (ea *MultiAuthKeyAuthenticator) UnmarshalBCS(des *bcs.Deserializer) {
	length := des.Uleb128()
	ea.PubKeys = make([]*AnyPublicKey, length)
	for i := uint32(0); i < length; i++ {
		ea.PubKeys[i] = &AnyPublicKey{}
		des.Struct(ea.PubKeys[i])
	}

	length = des.Uleb128()
	ea.Signatures = make([]*AnySignature, length)
	for i := uint32(0); i < length; i++ {
		ea.Signatures[i] = &AnySignature{}
		des.Struct(ea.Signatures[i])
	}
}

func fromAuthenticator(auth *AccountAuthenticator) (*AnyPublicKey, *AnySignature, error) {
	var variantPubkey AnyPublicKeyVariant
	var variantSig AnySignatureVariant

	switch auth.Variant {
	case AccountAuthenticatorEd25519:
		variantPubkey = AnyPublicKeyVariantEd25519
		variantSig = AnySignatureVariantEd25519
	case AccountAuthenticatorSingleSender:
		auth := auth.Auth.(*SingleKeyAuthenticator)
		return auth.PubKey, auth.Sig, nil
	default:
		return nil, nil, fmt.Errorf("unsupported authenticator type %d", auth.Variant)
	}

	pubkey := &AnyPublicKey{
		Variant: variantPubkey,
		PubKey:  auth.PubKey(),
	}
	sig := &AnySignature{
		Variant:   variantSig,
		Signature: auth.Signature(),
	}
	return pubkey, sig, nil
}
