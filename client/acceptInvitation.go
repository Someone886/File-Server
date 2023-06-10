package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Check for filename existance
	fileLookUpKey, err := userlib.HashKDF(userdata.FileLookupUUIDGenerator, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	fileLookUpUUID, err := uuid.FromBytes(fileLookUpKey[:16])
	if err != nil {
		return err
	}

	_, ok := userlib.DatastoreGet(fileLookUpUUID)

	if ok {
		return errors.New("file already exists")
	}

	// Fetch the invitation
	invitationData, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation UUID not found")
	}

	// Check bytes length
	if len(invitationData) < 256*3 {
		return errors.New("impossible whopper")
	}

	leftover, mainSign :=
		invitationData[:len(invitationData)-256], invitationData[len(invitationData)-256:]

	// Verify the main body: leftover
	senderPublicInvKey, ok := userlib.KeystoreGet(hex.EncodeToString(userlib.Hash([]byte(senderUsername))) + "Inv")
	if !ok {
		return errors.New("sender cannot be retrieved")
	}
	err = userlib.DSVerify(senderPublicInvKey, leftover, mainSign)
	if err != nil {
		return errors.New("cannot verify the leftover")
	}

	leftover, encryptedSymKey := leftover[:len(leftover)-256], leftover[len(leftover)-256:]
	encryptedInvitation, encryptedInvitationSign := leftover[:len(leftover)-256], leftover[len(leftover)-256:]

	senderPublicKey, ok := userlib.KeystoreGet(hex.EncodeToString(userlib.Hash([]byte(senderUsername))) + "Send")
	if !ok {
		return errors.New("sender cannot be retrieved")
	}

	// Verify sender signature then decrypt invitation
	err = userlib.DSVerify(senderPublicKey, encryptedInvitation, encryptedInvitationSign)
	if err != nil {
		return errors.New("cannot verify the sender")
	}

	// Decrypt symmetric key
	decryptedSymKey, err := userlib.PKEDec(userdata.UserPrivateKey, encryptedSymKey)
	if err != nil {
		// userlib.DebugMsg("private key: %v", userdata.UserPrivateKey)
		return errors.New("Cannot decrypt the invitation data " + err.Error())
	}

	decryptedInvitation := userlib.SymDec(decryptedSymKey, encryptedInvitation)

	var invitation Invitation
	err = json.Unmarshal(decryptedInvitation, &invitation)
	if err != nil {
		return err
	}

	// Verify that the invitation UUID matches
	if invitation.UUIDOfThisInvitation.String() != invitationPtr.String() {
		return errors.New("invitation UUID mismatch")
	}

	// Verify the file pointed is still valid
	_, ok = userlib.DatastoreGet(invitation.FilePointerUUID)
	if !ok {
		return errors.New("file pointed by invitation is invalid")
	}

	// Create file lookup from the invitation
	var lookUp FileLookup
	lookUp.Shared = true
	lookUp.FileHeaderSymKey = invitation.FilePointerSymKey
	lookUp.FileHeaderMacKey = invitation.HashedOwnerUsername
	lookUp.FileHeaderUUID = invitation.FilePointerUUID

	// Store the file lookup
	marshedLookUp, err := json.Marshal(lookUp)
	if err != nil {
		return err
	}

	fileLookUpEncKey, err := userlib.HashKDF(userdata.FileLookupRootEncKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}
	fileLookUpEncKey = fileLookUpEncKey[:16]

	fileLookUpMacKey, err := userlib.HashKDF(userdata.FileLookupRootSignKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}
	fileLookUpMacKey = fileLookUpMacKey[:16]

	lookUpIV := userlib.RandomBytes(16)
	encryptedLookUp := userlib.SymEnc(fileLookUpEncKey, lookUpIV, marshedLookUp)
	encryptedLookUpMac, err := userlib.HMACEval(fileLookUpMacKey, encryptedLookUp)
	if err != nil {
		return err
	}

	encryptedLookUpData := append(encryptedLookUp, encryptedLookUpMac...)
	userlib.DatastoreSet(fileLookUpUUID, encryptedLookUpData)

	return nil
}
