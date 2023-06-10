package client

import (
	_ "strconv"

	userlib "github.com/cs161-staff/project2-userlib"
)

type User struct {
	FileLookupRootEncKey    []byte
	FileLookupRootSignKey   []byte
	FileLookupUUIDGenerator []byte
	InvitationTablePointer  userlib.UUID
	InvitationTableSymKey   []byte
	InvitationTableSignKey  []byte
	FUIDPtrRootKey          []byte
	UserPrivateKey          userlib.PKEDecKey
	UserSendSign            userlib.DSSignKey //used to sign invitations
	UserOwnSign             userlib.DSSignKey // used to sign file pointers
	UserInvSign             userlib.DSSignKey // used to sign invitation symmetric key
	HashedUsername          []byte
}

type InvitationEntry struct {
	HashedRecipentUsername []byte
	FilePointerSymKey      []byte
	FilePointerUUID        userlib.UUID
	HashedFileName         []byte
	InvitationUUID         userlib.UUID
}

type InvitationTable struct {
	InvitationTable map[string]InvitationEntry
}

type Invitation struct {
	HashedOwnerUsername  []byte
	FilePointerUUID      userlib.UUID
	FilePointerSymKey    []byte
	UUIDOfThisInvitation userlib.UUID
}

type FilePointer struct {
	FileHeaderUUID       userlib.UUID
	FileHeaderSymKey     []byte
	FileHeaderMacKey     []byte
	UUIDOfTheFilePointer userlib.UUID
}

type FileLookup struct {
	Shared           bool // true if shared, false if not shared, maybe not needed
	FileHeaderUUID   userlib.UUID
	FileHeaderSymKey []byte
	FileHeaderMacKey []byte
}

type FileHeader struct {
	FirstBlockUUID   userlib.UUID
	LastBlockUUID    userlib.UUID
	FirstBlockSymKey []byte
	FirstBlockMacKey []byte
	LastBlockSymKey  []byte // Do we need this?
	LastBlockMacKey  []byte
}

type FileBlock struct {
	Content         []byte
	NextBlockUUID   userlib.UUID
	NextBlockSymKey []byte
	NextBlockMacKey []byte
}
