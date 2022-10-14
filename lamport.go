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


func (l *Lamport) GenerateKey() ([]byte, []byte, error)  {
	var sk []byte
	var pk []byte

	h := l.hashFunc()

	for  i := 0; i < l.blockSize ; i++ {
		key1, err1 := randomByte(l.bytesPerblock)
		if err1 != nil {
			return nil, nil, err1
		}
		sk = append(sk, key1...)
		pk = append(pk, hashBlock(h, key1)...)
	}

	for  i := 0; i < l.blockSize ; i++ {
		key2, err2 := randomByte(l.bytesPerblock)
		if err2 != nil {
			return nil, nil, err2
		}
		sk = append(sk, key2...)
		pk = append(pk, hashBlock(h, key2)...)
	}

	return sk, pk, nil
}

func (l *Lamport) Sign(msg []byte, sk []byte) []byte {
	var sig []byte
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
		
		shift := (int(b) * l.blockSize * l.bytesPerblock) + (i * l.bytesPerblock)

		sig = append(sig, sk[ shift:shift+l.bytesPerblock]...)	
	}

	return sig
}

func (l *Lamport) Verify(msg []byte, sig []byte,  pk []byte) bool {
	h := l.hashFunc()
	hashed := hashBlock(h, msg)

	x := new(big.Int).SetBytes(hashed)

	var b uint64
	
	for  i := 0; i < l.blockSize; i++ {
		// same operation as  int << i & 1 
		if i == 0 {
			b = pickBit(x, 0)
		} else {
			b = pickBit(x, 1)
		}
	
		shift := (int(b) * l.blockSize * l.bytesPerblock) + (i * l.bytesPerblock)
		sigShit := (i * l.bytesPerblock)

		if !bytes.Equal( pk[shift:shift+l.bytesPerblock], hashBlock(h, sig[sigShit:sigShit+l.bytesPerblock]) ) {
			return false
		}
	}

	return true
}
