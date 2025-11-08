package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/box"
)

func main() {
	cliApp := cli.NewApp()

	cliApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "k, key",
			Usage: "name of your key",
		},
		cli.BoolFlag{
			Name: "c, create",
		},
		cli.StringFlag{
			Name:  "a, alice",
			Usage: "recipient/sender public key (hex-encoded)",
		},
		cli.StringFlag{
			Name:  "d, decrypt",
			Usage: "location of file to decrypt",
		},
		cli.StringFlag{
			Name:  "e, encrypt",
			Usage: "location of file to encrypt",
		},
		cli.StringFlag{
			Name:  "o, out",
			Usage: "location of encrypted/decrypted file",
		},
	}

	cliApp.Action = func(c *cli.Context) error {
		keyfile := c.String("key")
		if len(keyfile) == 0 {
			panic("no keyfile specified")
		}
		encryptFile := c.String("encrypt")
		decryptFile := c.String("decrypt")
		if len(encryptFile) > 0 {
			encrypt(c)
			return nil
		}
		if len(decryptFile) > 0 {
			decrypt(c)
			return nil
		}
		if c.Bool("create") {
			create(c)
			return nil
		}
		panic("specify -e or -d")
	}

	err := cliApp.Run(os.Args)
	if err != nil {
		fmt.Printf("error: %+v\n", err)
		os.Exit(1)
	}
}

type JSONKeys struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

func getKeys(path string) *AsymEncKeypair {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var jsonKeys JSONKeys
	err = json.Unmarshal(bs, &jsonKeys)
	if err != nil {
		panic(err)
	}

	privkey := AsymEncPrivkeyFromBytes(jsonKeys.Private)
	if err != nil {
		panic(err)
	}

	pubkey := AsymEncPubkeyFromBytes(jsonKeys.Public)
	if err != nil {
		panic(err)
	}

	return &AsymEncKeypair{
		AsymEncPubkey:  pubkey,
		AsymEncPrivkey: privkey,
	}
}

func create(c *cli.Context) {
	createFile := c.String("key")
	if len(createFile) == 0 {
		panic("no destination specified (use -c)")
	}

	keypair, err := GenerateAsymEncKeypair()
	if err != nil {
		panic(err)
	}

	jsonKeys := JSONKeys{
		Public:  keypair.AsymEncPubkey.Bytes(),
		Private: keypair.AsymEncPrivkey.Bytes(),
	}

	bs, err := json.Marshal(jsonKeys)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(createFile, bs, 0600)
	if err != nil {
		panic(err)
	}

	fmt.Println("your pubkey is", hex.EncodeToString(jsonKeys.Public))
}

func encrypt(c *cli.Context) {
	outfile := c.String("out")
	if len(outfile) == 0 {
		panic("specify --outfile")
	}
	keypair := getKeys(c.String("key"))
	aliceHex := c.String("alice")
	if len(aliceHex) == 0 {
		panic("specify --alice")
	}
	alicePubkey, err := AsymEncPubkeyFromHex(aliceHex)
	if err != nil {
		panic(err)
	}

	msgBytes, err := ioutil.ReadFile(c.String("encrypt"))
	if err != nil {
		panic(err)
	}

	sealed, err := keypair.SealMessageFor(alicePubkey, msgBytes)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(outfile, sealed, 0644)
	if err != nil {
		panic(err)
	}
}

func decrypt(c *cli.Context) {
	outfile := c.String("out")
	if len(outfile) == 0 {
		panic("specify --outfile")
	}
	keypair := getKeys(c.String("key"))
	aliceHex := c.String("alice")
	if len(aliceHex) == 0 {
		panic("specify --alice")
	}
	alicePubkey, err := AsymEncPubkeyFromHex(aliceHex)
	if err != nil {
		panic(err)
	}

	msgBytes, err := ioutil.ReadFile(c.String("decrypt"))
	if err != nil {
		panic(err)
	}

	sealed, err := keypair.OpenMessageFrom(alicePubkey, msgBytes)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(outfile, sealed, 0644)
	if err != nil {
		panic(err)
	}
}

type (
	AsymEncPrivkey [NACL_BOX_KEY_LENGTH]byte
	AsymEncPubkey  [NACL_BOX_KEY_LENGTH]byte

	AsymEncKeypair struct {
		*AsymEncPrivkey
		*AsymEncPubkey
	}
)

const (
	NACL_BOX_KEY_LENGTH   = 32
	NACL_BOX_NONCE_LENGTH = 24
)

var (
	ErrCannotDecrypt = errors.New("cannot decrypt")
)

func GenerateAsymEncKeypair() (*AsymEncKeypair, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AsymEncKeypair{
		AsymEncPrivkey: (*AsymEncPrivkey)(privateKey),
		AsymEncPubkey:  (*AsymEncPubkey)(publicKey),
	}, nil
}

func AsymEncPubkeyFromBytes(bs []byte) *AsymEncPubkey {
	var pk AsymEncPubkey
	copy(pk[:], bs)
	return &pk
}

func AsymEncPubkeyFromHex(s string) (*AsymEncPubkey, error) {
	bs, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var pk AsymEncPubkey
	copy(pk[:], bs)
	return &pk, nil
}

func (pubkey *AsymEncPubkey) Bytes() []byte {
	bs := make([]byte, NACL_BOX_KEY_LENGTH)
	copy(bs, (*pubkey)[:])
	return bs
}

func (pubkey *AsymEncPubkey) Hex() string {
	return hex.EncodeToString(pubkey.Bytes())
}

func (pubkey *AsymEncPubkey) String() string {
	return pubkey.Hex()
}

func (pubkey *AsymEncPubkey) MarshalJSON() ([]byte, error) {
	return []byte(`"` + pubkey.Hex() + `"`), nil
}

func (pubkey *AsymEncPubkey) UnmarshalStateBytes(bs []byte) error {
	k := AsymEncPubkeyFromBytes(bs)
	*pubkey = *k
	return nil
}

func (pubkey AsymEncPubkey) MarshalStateBytes() ([]byte, error) {
	return pubkey.Bytes(), nil
}

func AsymEncPrivkeyFromBytes(bs []byte) *AsymEncPrivkey {
	var pk AsymEncPrivkey
	copy(pk[:], bs)
	return &pk
}

func AsymEncPrivkeyFromHex(s string) (*AsymEncPrivkey, error) {
	bs, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var pk AsymEncPrivkey
	copy(pk[:], bs)
	return &pk, nil
}

func (privkey *AsymEncPrivkey) Bytes() []byte {
	bs := make([]byte, NACL_BOX_KEY_LENGTH)
	copy(bs, (*privkey)[:])
	return bs
}

func (privkey *AsymEncPrivkey) SealMessageFor(recipientPubKey *AsymEncPubkey, msg []byte) ([]byte, error) {
	// The shared key can be used to speed up processing when using the same
	// pair of keys repeatedly.
	var sharedEncryptKey [NACL_BOX_KEY_LENGTH]byte
	box.Precompute(&sharedEncryptKey, (*[NACL_BOX_KEY_LENGTH]byte)(recipientPubKey), (*[NACL_BOX_KEY_LENGTH]byte)(privkey))

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [NACL_BOX_NONCE_LENGTH]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	// This encrypts msg and appends the result to the nonce.
	encrypted := box.SealAfterPrecomputation(nonce[:], msg, &nonce, &sharedEncryptKey)

	return encrypted, nil
}

func (privkey *AsymEncPrivkey) OpenMessageFrom(senderPublicKey *AsymEncPubkey, msgEncrypted []byte) ([]byte, error) {
	// The shared key can be used to speed up processing when using the same
	// pair of keys repeatedly.
	var sharedDecryptKey [NACL_BOX_KEY_LENGTH]byte
	box.Precompute(&sharedDecryptKey, (*[NACL_BOX_KEY_LENGTH]byte)(senderPublicKey), (*[NACL_BOX_KEY_LENGTH]byte)(privkey))

	// The recipient can decrypt the message using the shared key. When you
	// decrypt, you must use the same nonce you used to encrypt the message.
	// One way to achieve this is to store the nonce alongside the encrypted
	// message. Above, we prefixed the message with the nonce.
	var decryptNonce [NACL_BOX_NONCE_LENGTH]byte
	copy(decryptNonce[:], msgEncrypted[:NACL_BOX_NONCE_LENGTH])
	decrypted, ok := box.OpenAfterPrecomputation(nil, msgEncrypted[NACL_BOX_NONCE_LENGTH:], &decryptNonce, &sharedDecryptKey)
	if !ok {
		return nil, ErrCannotDecrypt
	}
	return decrypted, nil
}
