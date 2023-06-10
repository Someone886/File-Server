package client

import (
	_ "strconv"

	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Check if the filename exists in owner's file space
	var lookUp FileLookup
	deriveddUUID, e := userlib.HashKDF(userdata.FileLookupUUIDGenerator, userlib.Hash([]byte(filename)))
	if e != nil {
		userlib.DebugMsg("e")
		return e
	}
	deeee, e := uuid.FromBytes(deriveddUUID[:16])
	if e != nil {
		userlib.DebugMsg("e")
		return e
	}
	userlib.DebugMsg("Revoke access for user: %v. The derived UUID for file lookup from the owner is %v", recipientUsername, deeee)
	err := getFileLookupFromFileName(userdata, filename, &lookUp)
	if err != nil {
		userlib.DebugMsg("Error in first getFileLookupFromFileName")
		return err
	}

	entries := map[string]InvitationEntry{}

	err = verifyMacAndLoadContents(&entries, userdata.InvitationTablePointer,
		userdata.InvitationTableSymKey, userdata.InvitationTableSignKey)
	if err != nil {
		return errors.New("Invitation table has been tampered with " + err.Error())
	}

	keysToBroadcast := make([]string, 0)
	target_index := ""

	for index, entry := range entries {
		//userlib.DebugMsg("Revoke access index length: %v, length of one hash as string: %v, length of one has: %v", len(index), len(hex.EncodeToString(userlib.Hash([]byte(filename)))), len(userlib.Hash([]byte(recipientUsername))))
		if index == hex.EncodeToString(userlib.Hash([]byte(filename)))+hex.EncodeToString(userlib.Hash([]byte(recipientUsername))) {
			target_index = index
			userlib.DatastoreDelete(entry.FilePointerUUID)
			userlib.DebugMsg("Deleting contents of fileuuid: %v", entry.FilePointerUUID)
		} else if EqualBytes(entry.HashedFileName, userlib.Hash([]byte(filename))) {
			keysToBroadcast = append(keysToBroadcast, index)
		}
	}

	delete(entries, target_index)

	// Move around the file
	wholeContent, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// Update file lookup
	newHeaderUUID := uuid.New()
	lookUp.FileHeaderUUID = newHeaderUUID
	newSymKey := userlib.RandomBytes(16)
	newMacKey := userlib.RandomBytes(16)
	lookUp.FileHeaderSymKey = newSymKey
	lookUp.FileHeaderMacKey = newMacKey

	// Store the file at the new UUID
	err = CreateFile(newHeaderUUID, newSymKey, newMacKey, wholeContent)
	if err != nil {
		return err
	}

	// Store the new file lookup
	derivedEncKey, err := userlib.HashKDF(userdata.FileLookupRootEncKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	derivedMacKey, err := userlib.HashKDF(userdata.FileLookupRootSignKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	derivedUUIDRoot, err := userlib.HashKDF(userdata.FileLookupUUIDGenerator, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	derivedUUID, err := uuid.FromBytes(derivedUUIDRoot[:16])
	userlib.DebugMsg("Revoke access for user: %v. Storing new fileLookup for user at location %v", recipientUsername, derivedUUID)
	if err != nil {
		return err
	}

	err = encryptThenMac(&lookUp, derivedUUID, derivedEncKey[:16], derivedMacKey[:16])
	if err != nil {
		return err
	}

	// Start the broadcast process
	filePointerVerifyKey, ok := userlib.KeystoreGet(hex.EncodeToString(userdata.HashedUsername) + "Own")
	if !ok {
		return errors.New("public verification key not found")
	}
	filePointerSignKey := userdata.UserOwnSign

	// loop over every key in keysToBrodcast
	for _, key := range keysToBroadcast {
		invEntry := entries[key]

		filePointerUUID := invEntry.FilePointerUUID
		filePointerSymKey := invEntry.FilePointerSymKey

		filePointerBytes, ok := userlib.DatastoreGet(filePointerUUID)
		if !ok {
			return errors.New("file pointer not found")
		}

		// Check bytes length
		if len(filePointerBytes) < 256 {
			return errors.New("impossible whopper")
		}

		encryptedFilePointer := filePointerBytes[:len(filePointerBytes)-256]
		encryptedFilePointerSignature := filePointerBytes[len(filePointerBytes)-256:]

		err = userlib.DSVerify(filePointerVerifyKey, encryptedFilePointer, encryptedFilePointerSignature)
		if err != nil {
			return err
		}

		decryptedFilePointer := userlib.SymDec(filePointerSymKey, encryptedFilePointer)

		var filePointer FilePointer
		err = json.Unmarshal(decryptedFilePointer, &filePointer)
		if err != nil {
			return err
		}

		if filePointer.UUIDOfTheFilePointer.String() != filePointerUUID.String() {
			return errors.New("file pointer swapped")
		}

		filePointer.FileHeaderUUID = newHeaderUUID
		filePointer.FileHeaderSymKey = newSymKey
		filePointer.FileHeaderMacKey = newMacKey

		marshalledFilePointer, err := json.Marshal(filePointer)
		if err != nil {
			return err
		}

		filePointerIV := userlib.RandomBytes(16)
		encryptedFilePointer = userlib.SymEnc(filePointerSymKey, filePointerIV, marshalledFilePointer)
		encryptedFilePointerSignature, err = userlib.DSSign(filePointerSignKey, encryptedFilePointer)
		if err != nil {
			return err
		}

		encryptedFilePointerBytes := append(encryptedFilePointer, encryptedFilePointerSignature...)
		userlib.DatastoreSet(filePointerUUID, encryptedFilePointerBytes)

	}

	// Store the new invitation table
	err = encryptThenMac(&entries, userdata.InvitationTablePointer, userdata.InvitationTableSymKey, userdata.InvitationTableSignKey)
	if err != nil {
		return err
	}

	return nil
}
