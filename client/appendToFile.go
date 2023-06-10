package client

import (
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var lookUp FileLookup

	err := getFileLookupFromFileName(userdata, filename, &lookUp)
	if err != nil {
		return errors.New("Error in AppendToFile caused by getFileLookupFromFileName: " + err.Error())
	}

	var fileHeader *FileHeader
	var lastBlock *FileBlock

	var fileHeaderUUID uuid.UUID
	var fileHeaderSymKey []byte
	var fileHeaderMacKey []byte

	if !lookUp.Shared {
		fileHeaderUUID = lookUp.FileHeaderUUID
		fileHeaderSymKey = lookUp.FileHeaderSymKey
		fileHeaderMacKey = lookUp.FileHeaderMacKey

		fileHeader, lastBlock, err = GetHeader_LastBlock(fileHeaderUUID, fileHeaderSymKey, fileHeaderMacKey)
		if err != nil {
			return err
		}
	} else {
		filePointer, err := GetFilePointer(lookUp)
		if err != nil {
			return err
		}

		fileHeaderUUID = filePointer.FileHeaderUUID
		fileHeaderSymKey = filePointer.FileHeaderSymKey
		fileHeaderMacKey = filePointer.FileHeaderMacKey

		fileHeader, lastBlock, err = GetHeader_LastBlock(fileHeaderUUID, fileHeaderSymKey, fileHeaderMacKey)
		if err != nil {
			return err
		}
	}
	nextBlockUUID := fileHeader.LastBlockUUID
	nextBlockSymKey := fileHeader.LastBlockSymKey
	nextBlockMacKey := fileHeader.LastBlockMacKey

	allContent := append(lastBlock.Content, content...)

	length := len(allContent)
	i := 0
	// Stop at the last - 1 block
	for ; i+1024 < length; i += 1024 {
		nextBlockUUID, nextBlockSymKey, nextBlockMacKey, err =
			StoreThisBlock(nextBlockUUID, nextBlockSymKey, nextBlockMacKey, allContent[i:i+1024])
		if err != nil {
			return err
		}
	}

	// Update the file header
	// Next block of the last - 1 block is the last block
	fileHeader.LastBlockUUID = nextBlockUUID
	fileHeader.LastBlockSymKey = nextBlockSymKey
	fileHeader.LastBlockMacKey = nextBlockMacKey

	// Storing last block. Discard last block's next block information as this is the last block.
	_, _, _, err =
		StoreThisBlock(nextBlockUUID, nextBlockSymKey, nextBlockMacKey, allContent[i:Min(length, i+1024)])
	if err != nil {
		return err
	}

	// Store the file header
	marshedFileHeader, err := json.Marshal(fileHeader)
	if err != nil {
		return err
	}

	fileHeaderIV := userlib.RandomBytes(16)
	encryptedFileHeader := userlib.SymEnc(fileHeaderSymKey, fileHeaderIV, marshedFileHeader)
	encryptedFileHeaderMac, err := userlib.HMACEval(fileHeaderMacKey, encryptedFileHeader)
	if err != nil {
		return err
	}

	encryptedFileHeaderData := append(encryptedFileHeader, encryptedFileHeaderMac...)
	userlib.DatastoreSet(fileHeaderUUID, encryptedFileHeaderData)

	return nil
}
