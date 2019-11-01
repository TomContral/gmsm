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

package sm3

import (
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"os"
	"testing"
)

func byteToString(b []byte) string {
	ret := ""
	for i := 0; i < len(b); i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	fmt.Println("ret = ", ret)
	return ret
}

// 功能测试 go test
func TestSm3(t *testing.T) {
	standardData := []byte{0x55,0xE1,0x2E,0x91,0x65,0x0D,0x2F,0xEC,0x56,0xEC,0x74,0xE1,0xD3,0xE4,0xDD,0xBF,0xCE,0x2E,0xF3,0xA6,0x58,0x90,0xC2,0xA1,0x9E,0xCF,0x88,0xA3,0x07,0xE7,0x6A,0x23}
	msg := []byte("test")
	err := ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	msg, err = ioutil.ReadFile("ifile")
	if err != nil {
		log.Fatal(err)
	}
	hw := New()
	hw.Write(msg)
	hash := hw.Sum(nil)
	if sa := testCompare(hash, standardData); sa != true {
		fmt.Printf("Error data!")
	}
	fmt.Println(hash)
	fmt.Printf("%s\n", byteToString(hash))
	hash1 := Sm3Sum(msg)
	if sa := testCompare(hash1, standardData); sa != true {
		fmt.Printf("Error data!")
	}
	fmt.Println(hash1)
	fmt.Printf("%s\n", byteToString(hash1))

}

// 性能测试 go test -bench=.*
func BenchmarkSm3(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	hw := New()
	for i := 0; i < t.N; i++ {

		hw.Sum(nil)
		Sm3Sum(msg)
	}
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
