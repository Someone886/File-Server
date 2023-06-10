package client

import (
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	fileLookUpKey, err := userlib.HashKDF(userdata.FileLookupUUIDGenerator, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}

	fileLookUpUUID, err := uuid.FromBytes(fileLookUpKey[:16])
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

	_, ok := userlib.DatastoreGet(fileLookUpUUID)
	if !ok {
		// UUID Unoccupied
		lookUp, err := CreateOwnerLookUp(fileLookUpUUID, fileLookUpEncKey, fileLookUpMacKey)
		if err != nil {
			return err
		}

		err = CreateFile(lookUp.FileHeaderUUID, lookUp.FileHeaderSymKey, lookUp.FileHeaderMacKey, content)
		if err != nil {
			return err
		}

	} else {
		var lookUp FileLookup
		err = verifyMacAndLoadContents(&lookUp, fileLookUpUUID, fileLookUpEncKey, fileLookUpMacKey)
		if err != nil {
			return err
		}

		if !lookUp.Shared {
			// Overwrite Owner's File
			// File Lookup remains the same. File header + file content blocks changed.
			err = CreateFile(lookUp.FileHeaderUUID, lookUp.FileHeaderSymKey,
				lookUp.FileHeaderMacKey, content)
			if err != nil {
				return err
			}
		} else {
			// Overwrite shared file
			// File Lookup + File Pointer remain the same. File header + file content blocks changed.
			err = OverwriteSharedFile(lookUp, content)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
