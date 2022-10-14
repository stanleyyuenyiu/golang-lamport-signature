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

func hashBlock(h hash.Hash , r []byte) []byte {
	h.Reset()
	h.Write(r)
	return h.Sum(nil)
}

func randomByte(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}


func NewLamport(h func() hash.Hash) *Lamport {
	return &Lamport{
		hashFunc: h,
	}
}

func (l *Lamport) GenerateKey() ([][][]byte, [][][]byte, error)  {

	var privateKeys [][][]byte
	var publicKeys [][][]byte
	privateKeys = append(privateKeys, [][]byte {}, [][]byte {})
	publicKeys = append(publicKeys, [][]byte {}, [][]byte {})
	h := l.hashFunc()

	for  i := 0; i < 256; i++ {
		key1, err1 := randomByte(32)
		key2, err2 := randomByte(32)

		if err1 != nil {
			return nil, nil, err1
		}

		if err2 != nil {
			return nil, nil, err2
		}
		if len(privateKeys) == 0 {
			privateKeys = append(privateKeys, [][]byte {})
		}
		privateKeys[0] = append(privateKeys[0], key1)
		privateKeys[1] = append(privateKeys[1], key2)
		
		publicKeys[0] = append(publicKeys[0], hashBlock(h, key1))
		publicKeys[1] = append(publicKeys[1], hashBlock(h, key2))

	}
	return privateKeys, publicKeys, nil
}

func (l *Lamport) Sign(msg []byte, sk [][][]byte) [][]byte {
	var sig [][]byte
	h := l.hashFunc()
	//hashes the message to a 256-bit hash
	encoded := hashBlock(h, msg)

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

func (l *Lamport) Verify(msg []byte, sig [][]byte,  pk [][][]byte) bool {
	h := l.hashFunc()
	encoded := hashBlock(h, msg)

	x := new(big.Int).SetBytes(encoded)

	var b uint64

	for  i := 0; i < 256; i++ {
		
		if i == 0 {
			b = pickBit(x, 0)
		} else {
			b = pickBit(x, 1)
		}

		hashSign := hashBlock(h, sig[i])
		
		if !bytes.Equal(pk[b][i], hashSign) {
			return false
		}
	}
	return true
}




func main() {
	msg := []byte("陳生")

	lamport := NewLamport(sha256.New)

	sk, pk, err := lamport.GenerateKey()

	if err != nil {
		fmt.Println("Error")
		return
	}

	sig := lamport.Sign(msg, sk)

	fmt.Println( lamport.Verify(msg, sig, pk) )
}
