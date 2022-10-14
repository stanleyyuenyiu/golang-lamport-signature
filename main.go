package main

import (
	"bytes"
	 "crypto/rand"
	 "crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)


type Keys struct {
	privateKeys [2][256][]byte
	publicKeys [2][256][]byte
}

func Hash(h hash.Hash, r []byte) []byte {
	h.Reset()
	h.Write(r)
	return h.Sum(nil)
}

func RandomByte(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateKey() (*Keys, error)  {

	var privateKeys [2][256][]byte
	var publicKeys [2][256][]byte
	h := sha256.New()

	for  i := 0; i < 256; i++ {

		key1,_ := RandomByte(32)
		key2,_ := RandomByte(32)

		privateKeys[0][i] = key1
		privateKeys[1][i] = key2
		publicKeys[0][i] = Hash(h, key1)
		publicKeys[1][i] = Hash(h, key2)
	}
	return &Keys{privateKeys: privateKeys, publicKeys: publicKeys}, nil
}



func Sign(msg []byte, sk [2][256][]byte) [256][]byte {
	var sig [256][]byte
	h := sha256.New()
	//hashes the message to a 256-bit hash
	encoded := Hash(h, msg)
	
	//convert byte[] to big int
	var bI big.Int
	x := bI.SetBytes(encoded)
	
	//fmt.Printf( "%b\n",x )
	//fmt.Printf( "%b\n",data )

	for  i := 0; i < 256; i++ {
		// same operation as  int << i & 1 
		
		b := new(big.Int).And( new(big.Int).Rsh(x, uint(i)), big.NewInt(1) ).Uint64()

		// b = 1 or 0
        sig[i] = sk[b][i]
	}
	return sig
}


func Verify(msg []byte, sig [256][]byte,  pk [2][256][]byte) bool {
	h := sha256.New()
	encoded := Hash(h, msg)
	
	var bI big.Int
	x := bI.SetBytes(encoded)

	for  i := 0; i < 256; i++ {
        b := new(big.Int).And( new(big.Int).Rsh(x, uint(i)), big.NewInt(1) ).Uint64()
		hashSign := Hash(h, sig[i])
        if !bytes.Equal(pk[b][i], hashSign) {
			return false
		}
	}
	return true
}

func main() {
	keys, _ := GenerateKey()
	msg := []byte("陳生")
	sig := Sign(msg, keys.privateKeys)
	fmt.Println( Verify(msg, sig, keys.publicKeys) )
}
