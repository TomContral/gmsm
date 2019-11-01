/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm4

import (
	"fmt"
	"log"
	"reflect"
	"testing"
)

// 功能测试 go test
func TestSM4(t *testing.T) {
	key := []byte("1234567890abcdef")
	fmt.Printf("key = %v\n", key)
	standardData := []byte{0x17,0xE6,0x53,0x83,0x2D,0xE3,0x73,0x33,0xD2,0x16,0xC6,0xBE,0x7C,0xF1,0x3E,0x6E}
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	WriteKeyToPem("key.pem", key, nil)
	key, err := ReadKeyFromPem("key.pem", nil)
	fmt.Printf("key = %v\n", key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("data = %x\n", data)
	c, err := NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	d0 := make([]byte, 16)
	c.Encrypt(d0, data)
	if sa := testCompare(d0, standardData); sa != true {
		fmt.Printf("Error data!")
	}
	fmt.Printf("d0 = %x\n", d0)
	d1 := make([]byte, 16)
	c.Decrypt(d1, d0)
	fmt.Printf("d1 = %x\n", d1)
	if sa := testCompare(data, d1); sa != true {
		fmt.Printf("Error data!")
	}
}

// 性能测试 go test -bench=.*
func BenchmarkSM4Enc(t *testing.B) {
	t.ReportAllocs()
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	WriteKeyToPem("key.pem", key, nil)
	key, err := ReadKeyFromPem("key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
	c, err := NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	d0 := make([]byte, 16)
	for i := 0; i < t.N; i++ {
		c.Encrypt(d0, data)
	}
}

// 性能测试 go test -bench=.*
func BenchmarkSM4Dec(t *testing.B) {
	t.ReportAllocs()
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	WriteKeyToPem("key.pem", key, nil)
	key, err := ReadKeyFromPem("key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
	c, err := NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	d0 := make([]byte, 16)
	c.Encrypt(d0, data)
	d1 := make([]byte, 16)
	for i := 0; i < t.N; i++ {
		c.Decrypt(d1, d0)
	}
}

// 功能测试 go test -bench=.*
func TestErrKeyLen(t *testing.T) {
	fmt.Printf("\n--------------test key len------------------")
	key := []byte("1234567890abcdefg")
	_, err := NewCipher(key)
	if err != nil {
		fmt.Println("\nError key len is ok!")
	}
	key = []byte("1234")
	_, err = NewCipher(key)
	if err != nil {
		fmt.Println("Error key len is ok!")
	}
	fmt.Println("------------------end----------------------")
}

func testCompare(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i, v := range key1 {
		if i == 1 {
			fmt.Println("type of v", reflect.TypeOf(v))
		}
		a := key2[i]
		if a != v {
			return false
		}
	}
	return true
}
