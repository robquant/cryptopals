package main

import ( "strings"
		 "fmt"
		 "math/rand"
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
		params = append(params, key + "=" + object[key])
	}
	result := strings.Join(params, "&")
	return result

}

func profile_for(login string) string {

	// function should not allow encoding metacharacters (& and =)
	escaped_login := strings.ReplaceAll(login, "&", "")
	escaped_login = strings.ReplaceAll(escaped_login, "=", "")

	object := map[string]string {
		"email": escaped_login,
		"uid": "10",
		"role": "user",
	}
	return encode(object)
}

func decode(input string) map[string] string {
	object := make(map[string]string)
	parts := strings.Split(input, "&")
	for _, part := range parts {
		param := strings.Split(part, "=")
		k, v := param[0], param[1]
		object[k] = v
	}
	return object
}

func main(){

	// {
	// 	  email: 'foo@bar.com',
	// 	  uid: 10,	
	// 	  role: 'user'
	//  }
	//profile_for("foo@bar.com")
	input := "foo=bar&baz=qux&zap=zazzle"
	object := decode(input)
	fmt.Printf("%v\n", object)
	fmt.Printf("%s\n", profile_for("foo@bar.com&role=admin"))
	encrypted := encrypt(profile_for("foo@bar.com"), key)
	fmt.Printf("%v\n", encrypted)
	fmt.Printf("%s\n", decrypt(encrypted, key))

	fmt.Printf("%v\n", encrypt(profile_for("eXail=foo@bar.com"), key))
	fmt.Printf("%v\n", encrypt(profile_for("email=foo@bar.com"), key))

	// the bloc is 16 then, because the first 16 are different
	// [218 29 26 197 57 171 166 150 156  84   8 125 183 128  60 209 203 66 101 159 166 117 53 210 85 122 244 7 117 130 203 176 164 136 52 
	// 232 115 5 77 185 232 37 123 52 217 114 241 52]

	// [ 30 12 97 215 74  90 243 119  16 145 103  94 208  78 189  46 203 66 101 159 166 117 53 210 85 122 244 7 117 130 203 176 164 136 52 23
	// 2 115 5 77 185 232 37 123 52 217 114 241 52]

	// email=foo@bar.com&uid=10&role=user

	// email=12345678999999999999999@usern.com&uid=10&role=user

	// email=12345678999999999999999@admin.com&uid=10&role=user

	// email=foo@bar.com&uid=10&role=user
}