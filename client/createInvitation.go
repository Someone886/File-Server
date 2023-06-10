package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	_ "strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Check if the recipient exists
	_, ok := userlib.KeystoreGet(hex.EncodeToString(userlib.Hash([]byte(recipientUsername))) + "Public")
	if !ok {
		return uuid.Nil, errors.New("recipient does not exist")
	}

	// get file UUID of the file to be shared
	var fileLookup FileLookup

	err = getFileLookupFromFileName(userdata, filename, &fileLookup)
	if err != nil {
		return uuid.Nil, err
	}

	var fileHeader FileHeader
	var invitation Invitation
	invitationUUID := uuid.New()

	if fileLookup.Shared {
		// we have to go through the file pointer struct

		var filePointer FilePointer
		// get file pointer UUID
		bytesFromDS, ok := userlib.DatastoreGet(fileLookup.FileHeaderUUID)
		if !ok {
			return uuid.Nil, errors.New("file pointer does not exist")
		}

		// verify signature of file pointer
		// get public key from keystore
		publicKey, ok := userlib.KeystoreGet(hex.EncodeToString(fileLookup.FileHeaderMacKey) + "Own")
		if !ok {
			return uuid.Nil, errors.New("public key does not exist")
		}

		// Check bytes length
		if len(bytesFromDS) < 256 {
			return uuid.Nil, errors.New("impossible whopper")
		}

		err = userlib.DSVerify(publicKey, bytesFromDS[:len(bytesFromDS)-256], bytesFromDS[len(bytesFromDS)-256:])
		if err != nil {
			return uuid.Nil, errors.New("file pointer has been tampered with")
		}

		// decrypt file pointer
		decryptedFilePointer := userlib.SymDec(fileLookup.FileHeaderSymKey, bytesFromDS[:len(bytesFromDS)-256])
		err = json.Unmarshal(decryptedFilePointer, &filePointer)
		if err != nil {
			return uuid.Nil, err
		}

		if fileLookup.FileHeaderUUID.String() != filePointer.UUIDOfTheFilePointer.String() {
			return uuid.Nil, errors.New("file pointer has been tampered with")
		}

		err = verifyMacAndLoadContents(&fileHeader, filePointer.FileHeaderUUID, filePointer.FileHeaderSymKey, filePointer.FileHeaderMacKey)
		if err != nil {
			return uuid.Nil, err
		}

		// make a new invitation struct
		invitation.HashedOwnerUsername = fileLookup.FileHeaderMacKey
		invitation.FilePointerSymKey = fileLookup.FileHeaderSymKey
		invitation.FilePointerUUID = fileLookup.FileHeaderUUID
		invitation.UUIDOfThisInvitation = invitationUUID
		storeInvitation(&invitation, invitationUUID, userdata.UserSendSign, userdata.UserInvSign, recipientUsername)
		return invitationUUID, nil

	} else {
		invitationTable := map[string]InvitationEntry{}

		err = verifyMacAndLoadContents(&invitationTable, userdata.InvitationTablePointer, userdata.InvitationTableSymKey, userdata.InvitationTableSignKey)
		if err != nil {
			return uuid.Nil, err
		}
		err = verifyMacAndLoadContents(&fileHeader, fileLookup.FileHeaderUUID, fileLookup.FileHeaderSymKey, fileLookup.FileHeaderMacKey)
		if err != nil {
			return uuid.Nil, err
		}

		// Try fetching old invitation from before
		entryKey := hex.EncodeToString(userlib.Hash([]byte(filename))) + hex.EncodeToString(userlib.Hash([]byte(recipientUsername)))
		potentialOldInv, exists := invitationTable[entryKey]
		if exists {
			// Fetching the old invitation UUID
			invitationUUID = potentialOldInv.InvitationUUID
			return invitationUUID, nil
		}

		// make a new File Pointer struct
		var filePointer FilePointer
		var UUIDToStoreFilePointer = uuid.New()
		filePointer.FileHeaderUUID = fileLookup.FileHeaderUUID
		filePointer.FileHeaderSymKey = fileLookup.FileHeaderSymKey
		filePointer.FileHeaderMacKey = fileLookup.FileHeaderMacKey
		filePointer.UUIDOfTheFilePointer = UUIDToStoreFilePointer

		// marshall, encrypt and sign the file pointer
		randomBytesForFilePointerSymKey := userlib.RandomBytes(16)
		filePointerSymEncKey := randomBytesForFilePointerSymKey
		filePointerSignKey := userdata.UserOwnSign
		filePointerBytes, err := json.Marshal(filePointer)
		filePointerEncIV := userlib.RandomBytes(16)
		if err != nil {
			return uuid.Nil, errors.New("Marshalling file error " + err.Error())
		}

		filePointerEncrypted := userlib.SymEnc(filePointerSymEncKey, filePointerEncIV, filePointerBytes)
		filePointerSignature, err := userlib.DSSign(filePointerSignKey, filePointerEncrypted)
		if err != nil {
			return uuid.Nil, errors.New("File Pointer Signature error " + err.Error())
		}
		filePointerEncryptedAndSigned := append(filePointerEncrypted, filePointerSignature...)
		userlib.DatastoreSet(UUIDToStoreFilePointer, filePointerEncryptedAndSigned)

		// make a new invitation
		invitation.HashedOwnerUsername = userdata.HashedUsername
		invitation.FilePointerUUID = UUIDToStoreFilePointer
		invitation.FilePointerSymKey = filePointerSymEncKey
		invitation.UUIDOfThisInvitation = invitationUUID

		err = storeInvitation(&invitation, invitationUUID, userdata.UserSendSign, userdata.UserInvSign, recipientUsername)
		if err != nil {
			return uuid.Nil, err
		}

		// add invitation to invitation table
		invitationTableEntry := InvitationEntry{
			FilePointerSymKey:      randomBytesForFilePointerSymKey,
			FilePointerUUID:        UUIDToStoreFilePointer,
			HashedRecipentUsername: userlib.Hash([]byte(recipientUsername)),
			HashedFileName:         userlib.Hash([]byte(filename)),
			InvitationUUID:         invitationUUID,
		}

		invitationTable[entryKey] = invitationTableEntry

		// marshall, encrypt and sign the invitation table
		marshalledInvitationTable, err := json.Marshal(invitationTable)
		if err != nil {
			return uuid.Nil, err
		}
		encryptedInvitationTableIV := userlib.RandomBytes(16)
		encryptedInvitationTable := userlib.SymEnc(userdata.InvitationTableSymKey, encryptedInvitationTableIV, marshalledInvitationTable)
		invitationTableHmacTag, err := userlib.HMACEval(userdata.InvitationTableSignKey, encryptedInvitationTable)
		if err != nil {
			return uuid.Nil, err
		}
		encryptedInvitationTableBytes := append(encryptedInvitationTable, invitationTableHmacTag...)
		userlib.DatastoreSet(userdata.InvitationTablePointer, encryptedInvitationTableBytes)

		return invitationUUID, nil
	}
}
