package lamport

import (
	"bytes"
	"crypto/rand"
	"hash"
	"math/big"
	"errors"
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

func (l *Lamport) GenerateKey() (sk []byte, pk []byte, err error)  {
	
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

func (l *Lamport) Sign(msg []byte, sk []byte) (sig []byte, err error) {

	if len(sk) < l.bytesPerblock * l.blockSize * 2 {
		return nil, errors.New("Lamport: private key size doesn't match the scheme")
	}

	h := l.hashFunc()
	//hashes the message to a 256-bit hash
	hashed := hashBlock(h, msg)

	//convert byte[] to big int
	x := new(big.Int).SetBytes(hashed)
	
	for  i := 0; i < l.blockSize; i++ {
		sig = append(sig, l.PickBlockFromKeys( x, i, sk )...)	
	}

	return sig, nil
}

func (l *Lamport) Verify(msg []byte, sig []byte,  pk []byte) bool {

	if len(pk) < l.bytesPerblock * l.blockSize * 2 || len(sig) < l.bytesPerblock * l.blockSize  {
		return false
	}

	h := l.hashFunc()
	hashed := hashBlock(h, msg)

	x := new(big.Int).SetBytes(hashed)

	for  i := 0; i < l.blockSize; i++ {
		shift := (i * l.bytesPerblock)
		block := sig[shift:shift+l.bytesPerblock]

		if !bytes.Equal( l.PickBlockFromKeys( x, i, pk ), hashBlock(h, block) ) {
			return false
		}
	}

	return true
}

func (l *Lamport) PickBlockFromKeys( x *big.Int, index int , block []byte)  []byte {
	var b uint64
	// same operation as int << 1 & 1 
	// x is pointer, hence we either shift 0 or 1
		
	if index == 0 {
		b = pickBit(x, 0)
	} else {
		b = pickBit(x, 1)
	}

	shift := (int(b) * l.blockSize * l.bytesPerblock) + (index * l.bytesPerblock)

	return block[shift:shift+l.bytesPerblock]
}
