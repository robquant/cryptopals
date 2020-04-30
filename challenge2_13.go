package main

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/robquant/cryptopals/pkg/tools"
)

var key []byte

func init() {
	key = make([]byte, 16)
	rand.Read(key)
}

func decrypt(encrypted []byte, key []byte) []byte {
	result := tools.DecryptAesECB([]byte(encrypted), key)
	return result
}

func encrypt(userProfile string, key []byte) []byte {
	result := tools.EncryptAesECB([]byte(userProfile), key)
	return result
}

func encode(object map[string]string) string {
	params := make([]string, 0)
	keys := []string{"email", "uid", "role"}
	for _, key := range keys {
		params = append(params, key+"="+object[key])
	}
	result := strings.Join(params, "&")
	return result
}

func profile_for(login string) string {

	// function should not allow encoding metacharacters (& and =)
	escaped_login := strings.ReplaceAll(login, "&", "")
	escaped_login = strings.ReplaceAll(escaped_login, "=", "")

	object := map[string]string{
		"email": escaped_login,
		"uid":   "10",
		"role":  "user",
	}
	return encode(object)
}

func decode(input string) map[string]string {
	object := make(map[string]string)
	parts := strings.Split(input, "&")
	for _, part := range parts {
		param := strings.Split(part, "=")
		k, v := param[0], param[1]
		object[k] = v
	}
	return object
}

func main() {

	// {
	// 	  email: 'foo@bar.com',
	// 	  uid: 10,
	// 	  role: 'user'
	//  }
	//profile_for("foo@bar.com")
	// input := "foo=bar&baz=qux&zap=zazzle"
	// object := decode(input)
	// fmt.Printf("%v\n", object)
	// fmt.Printf("%s\n", profile_for("foo@bar.com&role=admin"))
	// encrypted := encrypt(profile_for("foo@bar.com"), key)
	// fmt.Printf("%v\n", encrypted)
	// fmt.Printf("%s\n", decrypt(encrypted, key))

	// fmt.Printf("%v\n", encrypt(profile_for("foX@bar.com"), key))
	// fmt.Printf("%v\n", encrypt(profile_for("foo@bar.com"), key))

	// the bloc is 16 then, because the first 16 are different

	// [213 223 241  63 213  58 116  70 231 188 223 83    7 238  68  20
	//  126 186 136 160 192  75   1 112 145   1  82 198 220 172 102 113
	//   62  44 183 210 239 182 246  55 233 240  22 134 239 207  21  56]

	// [207 203  67 117 178 156 149 253 189 46 255 193 148 151 39
	//  191 126 186 136 160 192 75 1 112 145 1 82 198 22 0 172 102 113 62 44 183 210 239 182 246 55 233 240 22 134 239 207 21 56]

	// email=foo@bar.com&uid=10&role=user

	// email=12345678999999999999999@usern.com&uid=10&role=user

	// email=123456789@admin.com&uid=10&role=user

	// email=foo@bar.com&uid=10&role=user

	// email=foo@bar.com&uid=10&role=user&role=admin

	// &role=admin it will 16 bytes, a block

	// email=foo@bar.com&uid=10&role=user 3 blocks

	// 1. keep changing the email until this goes to the last block:
	// &role=user

	// 2. we need to have this encrypted as last block:
	// &role=admin

	// 3. we will change just the last block with the admin one.

	fmt.Printf("% X\n", encrypt(profile_for("A23456789@admin.com"), key))

	// email=123456789@
	// admin.com&uid=10
	// &role=user......
	// C2 CD D0 02 13 56 59 3A D4 71 8F 06 F9 2B 33 99
	// 60 A6 29 BD 9E B9 CB 0B E1 B7 FD 5B 5A C2 D5 EF
	// A6 F0 8B 2B 57 9C E8 0B 48 C0 45 F5 7E 98 14 7F

	// CF 3B BC 43 C8 67 1A F0 65 E6 ED B5 F2 95 D6 AC
	// 60 A6 29 BD 9E B9 CB 0B E1 B7 FD 5B 5A C2 D5 EF
	// A6 F0 8B 2B 57 9C E8 0B 48 C0 45 F5 7E 98 14 7F

	// 1.
	// email=123456789@
	// c.m&uid=10&role=
	// user.............

	// 2. 123456789@admin           c.m
	// email=123456789@
	// admin
	// adminXXXXXXXXXXX
	// c.m&uid=10&role=
	// user.............

	// admin............
	//adminXXXXXXXXXXX

	// C2 CD D0 02 13 56 59 3A D4 71 8F 06 F9 2B 33 99
	// 60 A6 29 BD 9E B9 CB 0B E1 B7 FD 5B 5A C2 D5 EF
	// A6 F0 8B 2B 57 9C E8 0B 48 C0 45 F5 7E 98 14 7F

	// CF 3B BC 43 C8 67 1A F0 65 E6 ED B5 F2 95 D6 AC
	// 60 A6 29 BD 9E B9 CB 0B E1 B7 FD 5B 5A C2 D5 EF
	// A6 F0 8B 2B 57 9C E8 0B 48 C0 45 F5 7E 98 14 7F

	// email=123456789@
	// adminXXXXXXXXXXX
	// &role=user......
	// C2 CD D0 02 13 56 59 3A D4 71 8F 06 F9 2B 33 99
	// 60 A6 29 BD 9E B9 CB 0B E1 B7 FD 5B 5A C2 D5 EF
	// A6 F0 8B 2B 57 9C E8 0B 48 C0 45 F5 7E 98 14 7F

	// CF 3B BC 43 C8 67 1A F0 65 E6 ED B5 F2 95 D6 AC
	// 60 A6 29 BD 9E B9 CB 0B E1 B7 FD 5B 5A C2 D5 EF
	// A6 F0 8B 2B 57 9C E8 0B 48 C0 45 F5 7E 98 14 7F

	// "email=foo@bar.com&uid=10&role=admin           "

	// "role=admin\0x00           "
	// k="role"
	// v="admin           "
}
