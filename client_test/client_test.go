package client_test

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	"errors"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

// func TestSetupAndExecution(t *testing.T) {
// 	RegisterFailHandler(Fail)
// 	RunSpecs(t, "Client Tests")
// }

const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = " I love Bitcoin!"
const contentFive = " I love Ethereum!"

const length100 = string('a' * 100)
const length10000000 = string('a' * 10000000)

func TestALl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Everything ...")
}

var _ = Describe("Duplicate Invitations", func() {
	var alice *client.User
	var faceless *client.User
	var aliceLaptop *client.User
	var bob *client.User

	var err error

	aliceFile := "aliceFile.txt"
	aliceFile2 := "aliceFile2.txt"

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Swapping Tests", func() {

		Specify("Swapping test", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user faceless.")
			faceless, err = client.InitUser("faceless", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Faceless.")
			_, err = client.GetUser("faceless", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create file 1 for Alice.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create file 2 for Alice.")
			err = aliceLaptop.StoreFile(aliceFile2, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares file 1 with Faceless")
			file1_inv1, err := alice.CreateInvitation(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares file 1 with Faceless again")
			file1_inv2, err := alice.CreateInvitation(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares file 1 with Faceless again again")
			file1_inv3, err := alice.CreateInvitation(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares file 1 with Faceless again again again")
			file1_inv4, err := alice.CreateInvitation(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 4 for file 1 but duplicated filename.")
			err = faceless.StoreFile("facelessFile1", []byte(contentOne))
			Expect(err).To(BeNil())
			err = faceless.AcceptInvitation("alice", file1_inv4, "facelessFile1.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 4 for file 1.")
			err = faceless.AcceptInvitation("alice", file1_inv4, "facelessSharedFile1.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes file 1 on Faceless.")
			err = aliceLaptop.RevokeAccess(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless tries to access file 1.")
			_, err = faceless.LoadFile("facelessSharedFile1.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Faceless tries to accepts invitation 1 - 4 for file 1.")
			err = faceless.AcceptInvitation("alice", file1_inv1, "trying hard.txt")
			Expect(err).ToNot(BeNil())
			err = faceless.AcceptInvitation("alice", file1_inv2, "trying hard.txt")
			Expect(err).ToNot(BeNil())
			err = faceless.AcceptInvitation("alice", file1_inv3, "trying hard.txt")
			Expect(err).ToNot(BeNil())
			err = faceless.AcceptInvitation("alice", file1_inv4, "trying hard.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice shares file 2 with Bob")
			file2_inv, err := alice.CreateInvitation(aliceFile2, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invitation for file 2.")
			err = bob.AcceptInvitation("alice", file2_inv, "bobSharedFile2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob shares file 2 with Faceless.")
			file2_inv1_bob, err := bob.CreateInvitation("bobSharedFile2.txt", "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob shares file 2 with Faceless again.")
			file2_inv2_bob, err := bob.CreateInvitation("bobSharedFile2.txt", "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob shares file 2 with Faceless again again.")
			file3_inv3_bob, err := bob.CreateInvitation("bobSharedFile2.txt", "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 3 for file 2 from Bob.")
			err = faceless.AcceptInvitation("bob", file3_inv3_bob, "facelessSharedFile2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes file 2 on Bob.")
			err = aliceLaptop.RevokeAccess(aliceFile2, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless tries to access file 2.")
			_, err = faceless.LoadFile("facelessSharedFile2.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Faceless tries to accepts invitation 1 - 3 for file 2.")
			err = faceless.AcceptInvitation("bob", file2_inv1_bob, "trying hard 2.txt")
			Expect(err).ToNot(BeNil())
			err = faceless.AcceptInvitation("bob", file2_inv2_bob, "trying hard 2.txt")
			Expect(err).ToNot(BeNil())
			err = faceless.AcceptInvitation("bob", file3_inv3_bob, "trying hard 2.txt")
			Expect(err).ToNot(BeNil())

		})
	})
})

var _ = Describe("Swapping Tests", func() {
	var alice *client.User
	var faceless *client.User
	var aliceLaptop *client.User

	var err error

	aliceFile := "aliceFile.txt"
	aliceFile2 := "aliceFile2.txt"

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Swapping Tests", func() {

		Specify("Swapping test", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Wrong password test.")
			_, err = client.GetUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Wrong username test.")
			_, err = client.GetUser("alicee", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user faceless.")
			faceless, err = client.InitUser("faceless", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Faceless.")
			_, err = client.GetUser("faceless", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create file 1 for Alice.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create file 2 for Alice.")
			err = aliceLaptop.StoreFile(aliceFile2, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares file 1 with Faceless")
			inv1, err := alice.CreateInvitation(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares file 2 with Faceless")
			inv2, err := alice.CreateInvitation(aliceFile2, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 1 but wrong sendername.")
			err = faceless.AcceptInvitation("alicee", inv1, "facelessFile1.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 1.")
			err = faceless.AcceptInvitation("alice", inv1, "facelessFile1.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 2 but swapped invitation content.")
			Inv2Content, ok := userlib.DatastoreGet(inv2)
			fakeInv2UUID := uuid.New()
			userlib.DatastoreSet(fakeInv2UUID, Inv2Content)
			Expect(ok).To(BeTrue())
			err = faceless.AcceptInvitation("alice", fakeInv2UUID, "facelessFile2.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Faceless accepts invitation 2.")
			err = faceless.AcceptInvitation("alice", inv2, "facelessFile2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes file 1 on Faceless.")
			err = aliceLaptop.RevokeAccess(aliceFile, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless tries to access file 1.")
			_, err = faceless.LoadFile("facelessFile1.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Faceless tries to access file 2.")
			_, err = faceless.LoadFile("facelessFile2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes file 2 on Faceless.")
			err = aliceLaptop.RevokeAccess(aliceFile2, "faceless")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Faceless tries to access file 2.")
			_, err = faceless.LoadFile("facelessFile2.txt")
			Expect(err).ToNot(BeNil())
		})
	})
})

var _ = Describe("Client Tests", func() {

	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	//var frank *client.User
	//var grace *client.User
	//var horace *client.User
	//var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			// userlib.DebugMsg("Bob private key: %v", bob.UserPrivateKey)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			// userlib.DebugMsg("%s", data)

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing Revoke Functionality with multiple shared users", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice should be able to load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob should be able to load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)

			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that accessers cannot revoke access from file")
			err = bob.RevokeAccess(aliceFile, "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)

			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Ev can still load the file.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Testing Revoke with multiple appended blocks", func() {
			userlib.DebugMsg("Initializing Alice's desktop and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting Alice's laptop.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Instance aliceDesktop storing file with name %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Instance aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting invite with filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking that bob sees expected file data.")
			data1, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data2, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Testing LoadFile", func() {
			UUIDtoUser := map[userlib.UUID]bool{}
			var fileUUIDs []userlib.UUID

			userlib.DebugMsg("Initializing alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			for id := range userlib.DatastoreGetMap() {
				UUIDtoUser[id] = true
			}

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			for id := range userlib.DatastoreGetMap() {
				_, pre := UUIDtoUser[id]
				if !pre {
					fileUUIDs = append(fileUUIDs, id)
				}
			}

			userlib.DebugMsg("Loading file without integrity, error expected.")
			datastore := userlib.DatastoreGetMap()
			for _, id := range fileUUIDs {
				con := datastore[id]
				datastore[id][0] ^= 0x04
				_, err := alice.LoadFile(aliceFile)
				Expect(err).NotTo(BeNil())
				datastore[id][0] ^= 0x04
				_, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				datastore[id] = append(datastore[id], 0x05)
				_, err = alice.LoadFile(aliceFile)
				Expect(err).NotTo(BeNil())
				datastore[id] = con
				_, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				datastore[id] = datastore[id][0 : len(datastore[id])-1]
				_, err = alice.LoadFile(aliceFile)
				Expect(err).NotTo(BeNil())
				datastore[id] = con
				_, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
			}

			userlib.DebugMsg("Loading file with non used filename, error expected.")
			_, err := alice.LoadFile("invalidFilename")
			Expect(err).NotTo(BeNil())
		})

		Specify("Testing StoreFile", func() {
			userlib.DebugMsg("Initialize user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initialize user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Give bob access to file.")
			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accept invitation. As same name as alice")
			err = bob.AcceptInvitation("alice", invitation, aliceFile)
			Expect(err).To(BeNil())
			read, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Load shared file.")
			Expect(read).To(Equal([]byte(contentOne)))
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob tries to store file after alice revoked access.")
			err = bob.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Alice should still be able to read the file.")
			read, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(read).To(Equal([]byte(contentTwo)))
		})

		Specify("Testing AppendToFile", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Appending file with non used file name")
			err = alice.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).NotTo(BeNil())
		})

		Specify("Create invitation for non-existing user and filename.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file with data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice creating invalid invitation to non existing user.")
			_, err := alice.CreateInvitation(aliceFile, "eve")
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Alice creating invalid invitation to existing user but with non existing file name.")
			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Bob and alice store same file %s with same content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice creates invitation for %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting invite with existing filename %s", aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Bob accepting tampered invitation")
			datastore := userlib.DatastoreGetMap()
			datastore[invite][0] ^= 0x04
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).NotTo(BeNil())
			datastore[invite][0] ^= 0x04
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice storing file %s with content: %s", bobFile, contentOne)
			err = alice.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepts an invitation with wrong username.")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Alice creating invite for Bob for file %s", bobFile)
			invite, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice revoking Bob's access from %s.", bobFile)
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting revoked share link")
			err = bob.AcceptInvitation("alice", invite, "bobFile2")
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Alice creating share link of file %s.", aliceFile)
			_, err = alice.CreateInvitation(aliceFile, "bob")
		})
		Specify("Tree structure with multiple leaves of access", func() {
			userlib.DebugMsg("Initializing users.")
			users := []string{"alice", "bob", "charles", "doris", "eve", "frank", "grace", "horace", "ira"}
			var instances []*client.User
			for _, username := range users {
				instance, err := client.InitUser(username, defaultPassword)
				Expect(err).To(BeNil())
				instances = append(instances, instance)
			}
			userlib.DebugMsg("Initializing the file with with user alice.")
			err = instances[0].StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Building a tree structure Alice is at the top.")
			invite, err := instances[0].CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = instances[1].AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())
			invite, err = instances[0].CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())
			err = instances[4].AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Now bob shares the file with charles and doris.")
			invite, err = instances[1].CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = instances[2].AcceptInvitation("bob", invite, aliceFile)
			Expect(err).To(BeNil())
			invite, err = instances[1].CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())
			err = instances[3].AcceptInvitation("bob", invite, aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Now eve shares the file with frank and grace.")
			invite, err = instances[4].CreateInvitation(aliceFile, "frank")
			Expect(err).To(BeNil())
			err = instances[5].AcceptInvitation("eve", invite, aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("User appends to file")
			err = instances[3].AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			concatenatedContent := []byte(contentOne + contentTwo)
			userlib.DebugMsg("All users read the file and check if the content is correct.")
			for _, user := range instances[:6] {
				readContent, err := user.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(readContent).To(Equal(concatenatedContent))
			}
			userlib.DebugMsg("Alice revokes access from bob.")
			err = instances[0].RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = instances[5].AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			_, err = instances[3].LoadFile(aliceFile)
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Create new invitations to users ira and horace")
			invite, err = instances[4].CreateInvitation(aliceFile, "grace")
			Expect(err).To(BeNil())
			err = instances[6].AcceptInvitation("eve", invite, aliceFile)
			Expect(err).To(BeNil())
			invite, err = instances[0].CreateInvitation(aliceFile, "horace")
			Expect(err).To(BeNil())
			err = instances[7].AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())
			invite, err = instances[7].CreateInvitation(aliceFile, "ira")
			Expect(err).To(BeNil())
			err = instances[8].AcceptInvitation("horace", invite, aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check if the new users can read new file.")
			err = instances[6].AppendToFile(aliceFile, []byte(contentFour))
			Expect(err).To(BeNil())
			err = instances[8].AppendToFile(aliceFile, []byte(contentFive))
			Expect(err).To(BeNil())
			concatenatedContent = []byte(contentOne + contentTwo + contentThree + contentFour + contentFive)
			loadedContent, err := instances[0].LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(concatenatedContent))
			for _, user := range instances[4:] {
				loadedContent, err := user.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(loadedContent).To(Equal(concatenatedContent))
			}
		})

		Specify("Bandwidth test", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Adding short file and long file.")
			err = alice.StoreFile(aliceFile, []byte(length100))
			Expect(err).To(BeNil())
			err = alice.StoreFile(bobFile, []byte(length10000000))
			Expect(err).To(BeNil())
			measure := func(probe func()) (bandwidth int) {
				one := userlib.DatastoreGetBandwidth()
				probe()
				two := userlib.DatastoreGetBandwidth()
				return two - one
			}
			first := measure(func() {
				err = alice.AppendToFile(aliceFile, []byte(length10000000))
				Expect(err).To(BeNil())
			})
			second := measure(func() {
				err = alice.AppendToFile(bobFile, []byte(length10000000))
				Expect(err).To(BeNil())
			})

			if (first - second) < 1 {
				userlib.DebugMsg("Bandwith test passed. The difference is %d", first-second)
				err = nil
			} else {
				err = errors.New("The bandwidth is proportional to the size of file already stored.")
			}
			Expect(err).To(BeNil())
		})

		Specify("Edge cases", func() {
			userlib.DebugMsg("Case sensitive usernames")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Empty password")
			_, err = client.InitUser("bob", "")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Filename empty")
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Store empty file")
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
			data2, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte("")))
			userlib.DebugMsg("Overwritten file")
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data3, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(contentTwo)))
		})

		Specify("More edge cases", func() {
			userlib.DebugMsg("Initializing alice and bob and create file")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Alice overwrites the file now")
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob should read the overwrittenfile")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			userlib.DebugMsg("Alice appends empty file")
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
			data5, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data5).To(Equal([]byte(contentThree)))
		})

		Specify("Even more edge cases", func() {
			userlib.DebugMsg("Initializing alice, bob and charles")
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			invitation2, err := alice.CreateInvitation(aliceFile, "bob")
			userlib.DebugMsg("Charles hijacks the invitation")
			err = charles.AcceptInvitation("alice", invitation2, aliceFile)
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("Bob finally accepts the invitation")
			err = bob.AcceptInvitation("alice", invitation2, aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Charles tries to accept the invitation again")
			err = charles.AcceptInvitation("alice", invitation2, aliceFile)
			Expect(err).NotTo(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			invitation3, err := alice.CreateInvitation(aliceFile, "bob")
			err = eve.StoreFile(aliceFile, []byte(contentTwo))
			fakeInvite, err := eve.CreateInvitation(aliceFile, "bob")
			datastore := userlib.DatastoreGetMap()
			datastore[invitation3] = datastore[fakeInvite]
			err = bob.AcceptInvitation("alice", invitation3, aliceFile)
			Expect(err).NotTo(BeNil())
		})
	})

	Specify("Wrong sender", func() {
		alice, err = client.InitUser("alice", defaultPassword)
		bob, err = client.InitUser("bob", defaultPassword)
		alice.StoreFile(aliceFile, []byte(contentThree))
		shareFileInfoPtr, _ := alice.CreateInvitation(aliceFile, "bob")
		err := bob.AcceptInvitation("           ", shareFileInfoPtr, eveFile)
		Expect(err).ToNot(BeNil())
		err = bob.AcceptInvitation("RANDOM          ", shareFileInfoPtr, eveFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("Testing edge case inputs", func() {
		_, err = client.InitUser("\000", defaultPassword)
		Expect(err).To(BeNil())
		_, err = client.InitUser("\000", "\000")
		Expect(err).NotTo(BeNil())
		_, err = client.InitUser("g\000", "\000")
		Expect(err).To(BeNil())
		alice, err = client.InitUser("alice", defaultPassword)
		alice.AcceptInvitation("\000", uuid.UUID{}, "\000")
		bob, err = client.InitUser("bob", "bob")
		Expect(err).To(BeNil())
		alice.StoreFile("\000", []byte("....."))
		Expect(err).To(BeNil())
		alice.StoreFile("", []byte("\000"))
		Expect(err).To(BeNil())
		alice.AppendToFile("\000", []byte("\000"))
		Expect(err).To(BeNil())
		alice.CreateInvitation("\000", "\000")
		Expect(err).To(BeNil())
		alice.CreateInvitation("\000", "g\000")
		Expect(err).To(BeNil())
		inv, err := alice.CreateInvitation("\000", "bob")
		Expect(err).To(BeNil())
		bob.AcceptInvitation("alice", inv, "\000")
		Expect(err).To(BeNil())
		_, err = alice.LoadFile("\000")
		Expect(err).To(BeNil())
	})

	Specify("Accept invitation of yourself", func() {
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())
		inviteBob, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())
		err = bob.AcceptInvitation("bob", inviteBob, aliceFile)
		Expect(err).NotTo(BeNil())
		err = bob.StoreFile(aliceFile, []byte(contentFive))
		Expect(err).To(BeNil())
		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		alice.AppendToFile(aliceFile, []byte("g\r\ng"))
		Expect(err).To(BeNil())
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne + "g\r\ng")))
		charles, err := client.InitUser("charles", defaultPassword)
		Expect(err).To(BeNil())
		_, err = alice.CreateInvitation(aliceFile, "charles")
		Expect(err).To(BeNil())
		_, err = charles.LoadFile(aliceFile)
		Expect(err).NotTo(BeNil())
		alice.StoreFile("file1.txt", []byte(contentFour))
		pointer, _ := alice.CreateInvitation(contentFour, "bob")
		bob.StoreFile("file3.txt", []byte(contentFour))
		err = bob.AcceptInvitation("alice", pointer, "file3.txt")
		Expect(err).ToNot(BeNil())
		err = alice.RevokeAccess("", "bob")
		Expect(err).ToNot(BeNil())
		err = alice.RevokeAccess("\000", "")
		Expect(err).ToNot(BeNil())
	})

	Specify("Integrity for user", func() {
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		dataStore := userlib.DatastoreGetMap()
		for key, val := range dataStore {
			dataStore[key] = userlib.RandomBytes(len(val))
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).NotTo(BeNil())
			if err != nil {
				userlib.DebugMsg("Error was not nil")
			}
			dataStore[key] = val
		}
	})
})
