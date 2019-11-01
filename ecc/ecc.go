package ecc
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"crypto/elliptic"
)
var one = new(big.Int).SetInt64(1)
// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}


func pkcs7Padding(src []byte) []byte {
	padding := 32 - len(src)%32
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > 32 || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > 32 || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}


// 随机数域元素
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}
// ECC加密
func ECCEncrypt(pub *ecdsa.PublicKey, data []byte) ([]byte, error) {
	for {
		c := []byte{}
		//随机生成k使得1<=k<=n-1
		curve := pub.Curve
		k, err := randFieldElement(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		// P1 = [k]G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		c = append(c, x1Buf...) // x分量
		c = append(c, y1Buf...) // y分量
		// P2 = [k]Q
		x2, _ := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		if x2.Cmp(new(big.Int).SetUint64(0)) == 0 { // x2 != 0
			continue
		}
		// c = mx
		dataPadding := pkcs7Padding(data)
		m := new(big.Int).SetBytes(dataPadding[:32])
		d := new(big.Int).Mul(m, x2)// mx2
		P := curve.Params().P// save P
		d.Mod(d, P)// d = d mod P
		dBuf := d.Bytes()
		if n := len(dBuf); n < 32 {
			dBuf = append(zeroByteSlice()[:32-n], dBuf...)
		}
		c = append(c, dBuf...) // x分量
		return append([]byte{0x04}, c...), nil
	}
}
//ECC解密
func ECCDecrypt(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	data = data[1:]
	var err error
	curve := priv.Curve
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	c := new(big.Int).SetBytes(data[64:96])
	x2, _ := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
	}
	P := curve.Params().P
	w := new(big.Int).ModInverse(x2, P)
	m := new(big.Int).Mul(w, c)
	m.Mod(m, P)
	mBuf := m.Bytes()
	mBuf,err= pkcs7UnPadding(mBuf)
	if err != nil {
		return nil,err
	}
	return mBuf,nil
}
