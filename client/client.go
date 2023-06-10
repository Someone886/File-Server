package client

import (
	"encoding/hex"
	"encoding/json"

	"errors"
	_ "strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("empty Username")
	}

	var userdata User

	var userPublicKey userlib.PKEEncKey
	var userPrivateKey userlib.PKEDecKey
	var userSendVerifyKey userlib.DSVerifyKey
	var userSendSignKey userlib.DSSignKey
	var userOwnerVerify userlib.DSVerifyKey
	var userOwnerSign userlib.DSSignKey
	var this_uuid uuid.UUID

	userdata.FileLookupRootEncKey = userlib.RandomBytes(16)
	userdata.FileLookupRootSignKey = userlib.RandomBytes(16)
	userdata.FileLookupUUIDGenerator = userlib.RandomBytes(16)
	userdata.InvitationTablePointer = uuid.New()
	userdata.InvitationTableSymKey = userlib.RandomBytes(16)
	userdata.InvitationTableSignKey = userlib.RandomBytes(16)
	userdata.FUIDPtrRootKey = userlib.RandomBytes(16)
	userdata.HashedUsername = userlib.Hash([]byte(username))

	userPublicKey, userPrivateKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userInvSignKey, userInvVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	userSendSignKey, userSendVerifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userOwnerSign, userOwnerVerify, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	this_uuid, err = uuid.FromBytes(userlib.Hash(append([]byte(password), userlib.Hash([]byte(username))...))[:16])
	if err != nil {
		return nil, err
	}

	userdata.UserPrivateKey = userPrivateKey
	userdata.UserSendSign = userSendSignKey
	userdata.UserOwnSign = userOwnerSign
	userdata.UserInvSign = userInvSignKey

	err = userlib.KeystoreSet(hex.EncodeToString(userlib.Hash([]byte(username)))+"Public", userPublicKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(hex.EncodeToString(userlib.Hash([]byte(username)))+"Send", userSendVerifyKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(hex.EncodeToString(userlib.Hash([]byte(username)))+"Own", userOwnerVerify)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(hex.EncodeToString(userlib.Hash([]byte(username)))+"Inv", userInvVerifyKey)
	if err != nil {
		return nil, err
	}

	encryptedUserIV := userlib.RandomBytes(16)
	encryptedUserEncKey := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash(append([]byte(password), userlib.Hash([]byte(username))...)), uint32(userlib.AESKeySizeBytes))
	encryptedUserMacKey := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username)), uint32(userlib.AESKeySizeBytes))
	marshalledUser, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	encryptedUser := userlib.SymEnc(encryptedUserEncKey, encryptedUserIV, marshalledUser)
	userHmacTag, err := userlib.HMACEval(encryptedUserMacKey, encryptedUser)
	if err != nil {
		return nil, err
	}
	encryptedUserBytes := append(encryptedUser, userHmacTag...)
	userlib.DatastoreSet(this_uuid, encryptedUserBytes)

	// Make invitation table
	invitationTable := map[string]InvitationEntry{}

	marshalledInvitationTable, err := json.Marshal(invitationTable)
	if err != nil {
		return nil, err
	}
	encryptedInvitationTableIV := userlib.RandomBytes(16)
	encryptedInvitationTable := userlib.SymEnc(userdata.InvitationTableSymKey, encryptedInvitationTableIV, marshalledInvitationTable)
	invitationTableHmacTag, err := userlib.HMACEval(userdata.InvitationTableSignKey, encryptedInvitationTable)
	if err != nil {
		return nil, err
	}
	encryptedInvitationTableBytes := append(encryptedInvitationTable, invitationTableHmacTag...)
	userlib.DatastoreSet(userdata.InvitationTablePointer, encryptedInvitationTableBytes)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	_, ok := userlib.KeystoreGet(hex.EncodeToString(userlib.Hash([]byte(username))) + "Public")
	if !ok {
		return nil, errors.New("no such user")
	}

	derived_uuid, err := uuid.FromBytes(userlib.Hash(append([]byte(password), userlib.Hash([]byte(username))...))[:16])
	if err != nil {
		return nil, err
	}

	encryptedUserEncKey := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash(append([]byte(password), userlib.Hash([]byte(username))...)), uint32(userlib.AESKeySizeBytes))
	encryptedUserMacKey := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username)), uint32(16))

	var userdata User
	err = verifyMacAndLoadContents(&userdata, derived_uuid, encryptedUserEncKey, encryptedUserMacKey)
	if err != nil {
		return nil, err
	}

	var inv InvitationTable

	err = verifyMacAndLoadContents(&inv, userdata.InvitationTablePointer, userdata.InvitationTableSymKey, userdata.InvitationTableSignKey)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}
