package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	_ "strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// obj copied or original?
func verifyMacAndLoadContents(obj interface{}, uuid userlib.UUID, encKey []byte, macKey []byte) error {
	// get dacontents in datastore
	bytesFromDS, ok := userlib.DatastoreGet(uuid)
	/* if reflect.TypeOf(obj).String() == "*client.FileLookup" {
		userlib.DebugMsg("File lookup found in DS with uuid: %v", uuid)
	} */
	if !ok {
		//userlib.DebugMsg("File does not exist error when trying to get from Datastore, uuid: %v. Struct type: %v", uuid, reflect.TypeOf(obj).String())
		return errors.New("file does not exist")
	}

	// verify length
	if len(bytesFromDS) < 64 {
		return errors.New("impossible whopper")
	}

	// verify HMAC
	macTagProposal, err := userlib.HMACEval(macKey, bytesFromDS[:len(bytesFromDS)-64])
	if err != nil {
		return errors.New("mac Key invalid")
	}
	ok = userlib.HMACEqual(macTagProposal, bytesFromDS[len(bytesFromDS)-64:])
	if !ok {
		return errors.New("struct has been tampered with")
	}

	// decrypt file lookup
	decryptedStruct := userlib.SymDec(encKey, bytesFromDS[:len(bytesFromDS)-64])
	err = json.Unmarshal(decryptedStruct, obj)
	if err != nil {
		return errors.New("unable to unmarshal struct " + err.Error())
	}
	return nil
}

func encryptThenMac(obj interface{}, uuid userlib.UUID, encKey []byte, macKey []byte) error {
	encryptedStruct, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	randomIV := userlib.RandomBytes(16)
	encryptedStruct = userlib.SymEnc(encKey, randomIV, encryptedStruct)

	// generate HMAC
	macTag, err := userlib.HMACEval(macKey, encryptedStruct)
	if err != nil {
		return err
	}

	// store in datastore
	userlib.DatastoreSet(uuid, append(encryptedStruct, macTag...))
	return nil
}

func getFileLookupFromFileName(userdata *User, filename string, fileLookup *FileLookup) error {

	derivedSignKey, err := userlib.HashKDF(userdata.FileLookupRootSignKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	derivedEncKey, err := userlib.HashKDF(userdata.FileLookupRootEncKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	//userlib.DebugMsg("Appendfile -> getFileLookupFromFileName, derived mac Key is: %v, filename is: %v", derivedSignKey[:16], filename)

	derivedUUIDRoot, err := userlib.HashKDF(userdata.FileLookupUUIDGenerator, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	derivedUUID, err := uuid.FromBytes(derivedUUIDRoot[:16])
	if err != nil {
		return err
	}

	err = verifyMacAndLoadContents(fileLookup, derivedUUID, derivedEncKey[:16], derivedSignKey[:16])
	if err != nil {
		return errors.New("error in verifyMacAndLoadContents: " + err.Error())
	}
	return nil
}

func CreateOwnerLookUp(fileLookUpUUID uuid.UUID, fileLookUpEncKey []byte,
	fileLookUpMacKey []byte) (lookUpPtr *FileLookup, err error) {

	var lookUp FileLookup

	lookUp.Shared = false
	lookUp.FileHeaderSymKey = userlib.RandomBytes(16)
	lookUp.FileHeaderMacKey = userlib.RandomBytes(16)
	lookUp.FileHeaderUUID = uuid.New()

	lookUpIV := userlib.RandomBytes(16)
	marshedLookUp, err := json.Marshal(lookUp)
	if err != nil {
		return nil, err
	}

	encryptedLookUp := userlib.SymEnc(fileLookUpEncKey, lookUpIV, marshedLookUp)
	encryptedLookUpHmacTag, err := userlib.HMACEval(fileLookUpMacKey, encryptedLookUp)
	if err != nil {
		return nil, err
	}

	encryptMACLookUp := append(encryptedLookUp, encryptedLookUpHmacTag...)
	userlib.DatastoreSet(fileLookUpUUID, encryptMACLookUp)

	return &lookUp, err
}

func CreateFile(fileHeaderUUID uuid.UUID, fileHeaderSymKey []byte, fileHeaderMacKey []byte,
	content []byte) (err error) {

	var fileHeader FileHeader

	nextBlockUUID := uuid.New()
	fileHeader.FirstBlockUUID = nextBlockUUID

	nextBlockSymKey := userlib.RandomBytes(16)
	fileHeader.FirstBlockSymKey = nextBlockSymKey

	nextBlockMacKey := userlib.RandomBytes(16)
	fileHeader.FirstBlockMacKey = nextBlockMacKey

	length := len(content)
	i := 0
	// Stop at the last - 1 block
	for ; i+1024 < length; i += 1024 {
		nextBlockUUID, nextBlockSymKey, nextBlockMacKey, err =
			StoreThisBlock(nextBlockUUID, nextBlockSymKey, nextBlockMacKey, content[i:i+1024])
		if err != nil {
			return err
		}
	}

	// Next block of the last - 1 block is the last block
	fileHeader.LastBlockUUID = nextBlockUUID
	fileHeader.LastBlockSymKey = nextBlockSymKey
	fileHeader.LastBlockMacKey = nextBlockMacKey

	// Storing last block. Discard last block's next block information as this is the last block.
	_, _, _, err =
		StoreThisBlock(nextBlockUUID, nextBlockSymKey, nextBlockMacKey, content[i:Min(length, i+1024)])
	if err != nil {
		return err
	}

	err = encryptThenMac(fileHeader, fileHeaderUUID, fileHeaderSymKey, fileHeaderMacKey)
	if err != nil {
		return err
	}

	return nil
}

func GetFilePointer(lookUp FileLookup) (filePtr *FilePointer, err error) {
	filePointerUUID := lookUp.FileHeaderUUID
	filePointerSymKey := lookUp.FileHeaderSymKey
	filePointerOwnerHash := lookUp.FileHeaderMacKey

	filePointerOwnerVerify, ok := userlib.KeystoreGet(hex.EncodeToString(filePointerOwnerHash) + "Own")
	if !ok {
		return nil, errors.New("owner can't be found")
	}

	filePointerBytes, ok := userlib.DatastoreGet(filePointerUUID)
	if !ok {
		return nil, errors.New("file pointer not found")
	}

	// check byte length
	if len(filePointerBytes) < 256 {
		return nil, errors.New("impossible whopper")
	}

	encryptedFilePointer := filePointerBytes[:len(filePointerBytes)-256]
	encryptedFilePointerSignature := filePointerBytes[len(filePointerBytes)-256:]

	err = userlib.DSVerify(filePointerOwnerVerify, encryptedFilePointer, encryptedFilePointerSignature)
	if err != nil {
		return nil, errors.New("file pointer signature cannot be verified")
	}

	decryptedFilePointer := userlib.SymDec(filePointerSymKey, encryptedFilePointer)

	var filePointer FilePointer
	err = json.Unmarshal(decryptedFilePointer, &filePointer)
	if err != nil {
		return nil, err
	}

	if filePointer.UUIDOfTheFilePointer.String() != filePointerUUID.String() {
		userlib.DebugMsg("filePointer.UUIDOfTheFilePointer: %v", filePointer.UUIDOfTheFilePointer)
		userlib.DebugMsg("filePointerUUID: %v", filePointerUUID)
		userlib.DebugMsg("filePointer.FileHeaderUUID: %v", filePointer.FileHeaderUUID)
		return nil, errors.New("file pointer corrupted")
	}

	return &filePointer, nil
}

func StoreThisBlock(thisBlockUUID uuid.UUID, thisBlockEncKey []byte,
	thisBlockMacKey []byte, content []byte) (nextBlockUUID uuid.UUID,
	nextBlockSymKey []byte, nextBlockMacKey []byte, err error) {

	var thisBlock FileBlock
	thisBlock.NextBlockUUID = uuid.New()
	thisBlock.NextBlockSymKey = userlib.RandomBytes(16)
	thisBlock.NextBlockMacKey = userlib.RandomBytes(16)
	thisBlock.Content = content

	// userlib.DebugMsg("storing block's mac key: %v", thisBlockMacKey)
	// userlib.DebugMsg("storing block's UUID: %v", thisBlockUUID)

	err = encryptThenMac(&thisBlock, thisBlockUUID, thisBlockEncKey, thisBlockMacKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	return thisBlock.NextBlockUUID, thisBlock.NextBlockSymKey, thisBlock.NextBlockMacKey, nil
}

func GetHeader_LastBlock(fileHeaderUUID uuid.UUID, fileHeaderSymKey []byte,
	fileHeaderMacKey []byte) (header *FileHeader, block *FileBlock, err error) {
	var fileHeader FileHeader
	err = verifyMacAndLoadContents(&fileHeader, fileHeaderUUID, fileHeaderSymKey, fileHeaderMacKey)
	if err != nil {
		return nil, nil, err
	}

	var lastBlock FileBlock
	err = verifyMacAndLoadContents(&lastBlock, fileHeader.LastBlockUUID, fileHeader.LastBlockSymKey, fileHeader.LastBlockMacKey)
	if err != nil {
		return nil, nil, err
	}

	return &fileHeader, &lastBlock, nil
}

// Overwrite the shared file
func OverwriteSharedFile(lookUp FileLookup, content []byte) (err error) {
	filePointer, err := GetFilePointer(lookUp)
	if err != nil {
		return err
	}

	fileHeaderUUID := filePointer.FileHeaderUUID
	fileHeaderSymKey := filePointer.FileHeaderSymKey
	fileHeaderMacKey := filePointer.FileHeaderMacKey

	err = CreateFile(fileHeaderUUID, fileHeaderSymKey, fileHeaderMacKey, content)
	if err != nil {
		return err
	}

	return nil
}

func storeInvitation(invitation *Invitation, uuid uuid.UUID, messageSignKey userlib.PrivateKeyType, allSignKey userlib.PrivateKeyType, recipientUsername string) error {
	recipientPublicKey, ok := userlib.KeystoreGet(hex.EncodeToString(userlib.Hash([]byte(recipientUsername))) + "Public")
	if !ok {
		return errors.New("public key does not exist")
	}

	messageSymEncKey := userlib.RandomBytes(16)
	messageEncIV := userlib.RandomBytes(16)

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return err
	}
	invitationMessageEncrypted := userlib.SymEnc(messageSymEncKey, messageEncIV, invitationBytes)

	invitationMessageSignature, err := userlib.DSSign(messageSignKey, invitationMessageEncrypted)
	if err != nil {
		return errors.New("Invitation signature error " + err.Error())
	}
	invitationEncryptedAndSigned := append(invitationMessageEncrypted, invitationMessageSignature...)

	encryptedSymKeyWithRecipientsPublicKey, err := userlib.PKEEnc(recipientPublicKey, messageSymEncKey)
	if err != nil {
		return errors.New("error in encrypting sym key with recipient's public key " + err.Error())
	}

	pk, sk, _ := userlib.PKEKeyGen()
	ciphertext, err := userlib.PKEEnc(pk, messageSymEncKey)
	if err != nil {
		return errors.New("error in encrypting sym key with recipient's public key " + err.Error())
	}

	plaintext, err := userlib.PKEDec(sk, ciphertext)
	if err != nil {
		return errors.New("error in decrypting sym key with recipient's private key " + err.Error())
	}

	if !EqualBytes(plaintext, messageSymEncKey) {
		return errors.New("error in decrypting sym key with recipient's private key")
	}

	if err != nil {
		return errors.New("error in encrypting sym key with recipient's public key " + err.Error())
	}

	invitationEncryptedAndSigned = append(invitationEncryptedAndSigned, encryptedSymKeyWithRecipientsPublicKey...)

	allSignature, err := userlib.DSSign(allSignKey, invitationEncryptedAndSigned)
	if err != nil {
		return errors.New("invitation signature error " + err.Error())
	}

	invitationEncryptedAndSigned = append(invitationEncryptedAndSigned, allSignature...)

	userlib.DatastoreSet(uuid, invitationEncryptedAndSigned)
	return nil
}

func EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func Min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
