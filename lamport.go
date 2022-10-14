package lamport

import (
	"bytes"
	"crypto/rand"
	"hash"
	"math/big"
)

type Lamport struct {
	hashFunc  func() hash.Hash
	blockSize int
	bytesPerblock int
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
		blockSize: 256,
		bytesPerblock: 256/8,
	}
}

func (l *Lamport) GenerateKey() ([][][]byte, [][][]byte, error)  {

	var sk [][][]byte
	var pk [][][]byte
	sk = append(sk, [][]byte {}, [][]byte {})
	pk = append(pk, [][]byte {}, [][]byte {})
	
	h := l.hashFunc()

	for  i := 0; i < l.blockSize ; i++ {
		key1, err1 := randomByte(l.bytesPerblock)
		key2, err2 := randomByte(l.bytesPerblock)

		if err1 != nil {
			return nil, nil, err1
		}

		if err2 != nil {
			return nil, nil, err2
		}
		if len(sk) == 0 {
			sk = append(sk, [][]byte {})
		}
		sk[0] = append(sk[0], key1)
		sk[1] = append(sk[1], key2)
		
		pk[0] = append(pk[0], hashBlock(h, key1))
		pk[1] = append(pk[1], hashBlock(h, key2))

	}
	return sk, pk, nil
}

func (l *Lamport) Sign(msg []byte, sk [][][]byte) [][]byte {
	var sig [][]byte
	h := l.hashFunc()
	//hashes the message to a 256-bit hash
	hashed := hashBlock(h, msg)

	//convert byte[] to big int
	x := new(big.Int).SetBytes(hashed)
	
	var b uint64

	for  i := 0; i < l.blockSize; i++ {
		// same operation as int << 1 & 1 
		// x is pointer, hence we either shift 0 or 1
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
	hashed := hashBlock(h, msg)

	x := new(big.Int).SetBytes(hashed)

	var b uint64

	for  i := 0; i < 256; i++ {
		// same operation as  int << i & 1 
		if i == 0 {
			b = pickBit(x, 0)
		} else {
			b = pickBit(x, 1)
		}

		//compare hashedBlock with public key
		if !bytes.Equal( pk[b][i], hashBlock(h, sig[i]) ) {
			return false
		}
	}

	return true
}


