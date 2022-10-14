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


type Lamport struct {
	hashFunc  func() hash.Hash
}

func pickBit(x *big.Int, shiftOffset int) uint64 {
	x.Rsh(x, uint(shiftOffset))
	return new(big.Int).And( x, big.NewInt(1) ).Uint64()
}

func NewLamport(h func() hash.Hash) *Lamport {
	return &Lamport{
		hashFunc: h,
	}
}

func (l *Lamport) GenerateKey() ([2][256][]byte, [2][256][]byte, error)  {

	var privateKeys [2][256][]byte
	var publicKeys [2][256][]byte

	h := l.hashFunc()

	for  i := 0; i < 256; i++ {

		key1,_ := RandomByte(32)
		key2,_ := RandomByte(32)

		privateKeys[0][i] = key1
		privateKeys[1][i] = key2
		publicKeys[0][i] = Hash(h, key1)
		publicKeys[1][i] = Hash(h, key2)
	}
	return privateKeys, publicKeys, nil
}

func (l *Lamport) Sign(msg []byte, sk [2][256][]byte) [][]byte {
	var sig [][]byte
	h := l.hashFunc()
	//hashes the message to a 256-bit hash
	encoded := Hash(h, msg)

	//convert byte[] to big int
	x := new(big.Int).SetBytes(encoded)
	
	var b uint64

	for  i := 0; i < 256; i++ {
		// same operation as  int << i & 1 
		if i == 0 {
			b = pickBit(x, 0)
		} else {
			b = pickBit(x, 1)
		}
		
		// b = 1 or 0
		sig = append(sig, sk[b][i])
	}
	return sig
}

func (l *Lamport) Verify(msg []byte, sig [][]byte,  pk [2][256][]byte) bool {
	h := l.hashFunc()
	encoded := Hash(h, msg)

	x := new(big.Int).SetBytes(encoded)

	var b uint64

	for  i := 0; i < 256; i++ {
		
		if i == 0 {
			b = pickBit(x, 0)
		} else {
			b = pickBit(x, 1)
		}

		hashSign := Hash(h, sig[i])
		
		if !bytes.Equal(pk[b][i], hashSign) {
			return false
		}
	}
	return true
}

func Hash(h hash.Hash , r []byte) []byte {
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



func main() {
	msg := []byte("陳生")

	lamport := NewLamport(sha256.New)

	sk, pk, _ := lamport.GenerateKey()

	sig := lamport.Sign(msg, sk)
	
	fmt.Println( lamport.Verify(msg, sig, pk) )
}
