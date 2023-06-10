package client

import (
	_ "strconv"

	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	fileLookupRootSignKey := userdata.FileLookupRootSignKey
	fileLookupRootEncKey := userdata.FileLookupRootEncKey
	fileLookupUUIDGenerator := userdata.FileLookupUUIDGenerator

	var fileLookup FileLookup

	derivedSignKey, err := userlib.HashKDF(fileLookupRootSignKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return nil, err
	}
	//userlib.DebugMsg("Loadfile, the derived MAC key for file lookup: %v, filename is: %v", derivedSignKey[:16], filename)

	derivedEncKey, err := userlib.HashKDF(fileLookupRootEncKey, userlib.Hash([]byte(filename)))
	if err != nil {
		return nil, err
	}

	derivedUUIDRoot, err := userlib.HashKDF(fileLookupUUIDGenerator, userlib.Hash([]byte(filename)))
	if err != nil {
		return nil, err
	}

	derivedUUID, err := uuid.FromBytes(derivedUUIDRoot[:16])
	if err != nil {
		return nil, err
	}

	err = verifyMacAndLoadContents(&fileLookup, derivedUUID, derivedEncKey[:16], derivedSignKey[:16])
	if err != nil {
		userlib.DebugMsg("Error is in first verifyMacAndLoadContents ")
		return nil, err
	}

	var fileHeader FileHeader

	if fileLookup.Shared {
		// we have to go through the file pointer struct

		var filePointer FilePointer
		// get file pointer UUID
		bytesFromDS, ok := userlib.DatastoreGet(fileLookup.FileHeaderUUID)
		if !ok {
			return nil, errors.New("file pointer does not exist")
		}

		// verify signature of file pointer
		// get public key from keystore
		publicKey, ok := userlib.KeystoreGet(hex.EncodeToString(fileLookup.FileHeaderMacKey) + "Own")
		if !ok {
			return nil, errors.New("public key does not exist")
		}

		// Check bytes length
		if len(bytesFromDS) < 256 {
			return nil, errors.New("impossible whopper")
		}

		err = userlib.DSVerify(publicKey, bytesFromDS[:len(bytesFromDS)-256], bytesFromDS[len(bytesFromDS)-256:])
		if err != nil {
			return nil, errors.New("file pointer has been tampered with")
		}

		// decrypt file pointer
		decryptedFilePointer := userlib.SymDec(fileLookup.FileHeaderSymKey, bytesFromDS[:len(bytesFromDS)-256])
		err = json.Unmarshal(decryptedFilePointer, &filePointer)
		if err != nil {
			return nil, errors.New("file pointer cannot be unmarshalled")
		}

		if fileLookup.FileHeaderUUID.String() != filePointer.UUIDOfTheFilePointer.String() {
			return nil, errors.New("file pointer has been tampered with")
		}

		err = verifyMacAndLoadContents(&fileHeader, filePointer.FileHeaderUUID, filePointer.FileHeaderSymKey, filePointer.FileHeaderMacKey)
		if err != nil {
			return nil, errors.New("File header cannot be loaded from the shared file " + err.Error())
		}

	} else {
		err = verifyMacAndLoadContents(&fileHeader, fileLookup.FileHeaderUUID, fileLookup.FileHeaderSymKey, fileLookup.FileHeaderMacKey)
		if err != nil {
			return nil, errors.New("File header cannot be loaded from my own file " + err.Error())
		}
	}

	lastBlockUUID := fileHeader.LastBlockUUID
	blockUUID := fileHeader.FirstBlockUUID
	blockSymKey := fileHeader.FirstBlockSymKey
	blockMacKey := fileHeader.FirstBlockMacKey

	i := 0
	for {
		var fileBlock FileBlock

		// userlib.DebugMsg("block mac key is: %v", blockMacKey)
		// userlib.DebugMsg("block UUID is %v", blockUUID)

		err = verifyMacAndLoadContents(&fileBlock, blockUUID, blockSymKey, blockMacKey)
		if err != nil {
			return nil, errors.New("Blocked cannot be loaded from file header " + err.Error())
		}

		content = append(content, fileBlock.Content...)

		// if blockuuid is last block uuid, then we break
		if blockUUID == lastBlockUUID {
			break
		}

		blockUUID = fileBlock.NextBlockUUID
		blockSymKey = fileBlock.NextBlockSymKey
		blockMacKey = fileBlock.NextBlockMacKey

		i += 1
	}

	return content, nil
}
