package strivia

import (
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
)

/* Benchmarks */

func BenchmarkCreateHashDefaultParamsOWASP(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = CreateHash("P@ssw0rd", DefaultParamsOWASP)
	}
}

func BenchmarkCreateHashDefaultParamsRFC1(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = CreateHash("P@ssw0rd", DefaultParamsRFC1)
	}
}

func BenchmarkCreateHashRFC9106_2(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = CreateHash("P@ssw0rd", DefaultParamsRFC2)
	}
}

/* Tests */

const bugHash = "$argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE"

func TestCreateHash(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	hash1 := CreateHash("pa$$word", DefaultParamsOWASP)

	if !hashRX.MatchString(hash1) {
		t.Errorf("hash %q not in correct format", hash1)
	}

	hash2 := CreateHash("pa$$word", DefaultParamsOWASP)

	if strings.Compare(hash1, hash2) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestCreateHashBytes(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	password := make([]byte, 16)
	rand.Read(password)

	hash1 := CreateHash(password, DefaultParamsOWASP)

	if !hashRX.MatchString(hash1) {
		t.Errorf("hash %q not in correct format", hash1)
	}

	hash2 := CreateHash(password, DefaultParamsOWASP)

	if strings.Compare(hash1, hash2) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestComparePasswordAndHash(t *testing.T) {
	hash := CreateHash("pa$$word", DefaultParamsOWASP)

	match, err := ComparePasswordAndHash("pa$$word", hash)
	if err != nil {
		t.Fatal(err)
	}

	if !match {
		t.Error("expected password and hash to match")
	}

	match, err = ComparePasswordAndHash("otherPa$$word", hash)
	if err != nil {
		t.Fatal(err)
	}

	if match {
		t.Error("expected password and hash to not match")
	}
}

func TestComparePasswordAndHashBytes(t *testing.T) {
	password := make([]byte, 16)
	rand.Read(password)

	hash := CreateHash(password, DefaultParamsOWASP)

	match, err := ComparePasswordAndHash(password, hash)
	if err != nil {
		t.Fatal(err)
	}

	if !match {
		t.Error("expected password and hash to match")
	}

	otherPassword := make([]byte, 16)
	_, err = rand.Read(otherPassword)
	if err != nil {
		t.Fatal(err)
	}

	match, err = ComparePasswordAndHash(otherPassword, hash)
	if err != nil {
		t.Fatal(err)
	}

	if match {
		t.Error("expected password and hash to not match")
	}
}

func TestDecodeHash(t *testing.T) {
	hash := CreateHash("pa$$word", DefaultParamsOWASP)

	params, _, _, err := DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if *params != *DefaultParamsOWASP {
		t.Fatalf("expected %#v got %#v", *DefaultParamsOWASP, *params)
	}

	for _, c := range []string{"v", "m", "t", "p"} {
		re := regexp.MustCompile("([$,])(" + c + "=[^$,]+)")
		_, _, _, err = DecodeHash(re.ReplaceAllString(bugHash, "$1JUNK+$2"))
		if err == nil {
			t.Fatalf("leading %s key junk should fail decode", c)
		}
		_, _, _, err = DecodeHash(re.ReplaceAllString(bugHash, "$1$2+JUNK"))
		if err == nil {
			t.Fatalf("trailing %s value junk should fail decode", c)
		}
	}

	i := strings.LastIndex(bugHash, "$")
	_, _, _, err = DecodeHash(bugHash[:i] + "\r$\n" + bugHash[i+1:])
	if err == nil {
		t.Fatalf(`\r and \n in base64 data should fail decode`)
	}
}

func TestDecodeHashBytes(t *testing.T) {
	password := make([]byte, 16)
	rand.Read(password)

	hash := CreateHash(password, DefaultParamsOWASP)

	params, _, _, err := DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if *params != *DefaultParamsOWASP {
		t.Fatalf("expected %#v got %#v", *DefaultParamsOWASP, *params)
	}
}

func TestCheckHash(t *testing.T) {
	hash := CreateHash("pa$$word", DefaultParamsOWASP)

	ok, params, err := CheckHash("pa$$word", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}
	if *params != *DefaultParamsOWASP {
		t.Fatalf("expected %#v got %#v", *DefaultParamsOWASP, *params)
	}
}

func TestCheckHashBytes(t *testing.T) {
	password := make([]byte, 16)
	rand.Read(password)

	hash := CreateHash(password, DefaultParamsOWASP)

	ok, params, err := CheckHash(password, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}
	if *params != *DefaultParamsOWASP {
		t.Fatalf("expected %#v got %#v", *DefaultParamsOWASP, *params)
	}
}

func TestStrictDecoding(t *testing.T) {
	ok, _, err := CheckHash("bug", bugHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}

	ok, _, err = CheckHash("bug", bugHash[:len(bugHash)-1]+"F")
	if err == nil {
		t.Fatal("Hash validation should fail")
	}

	if ok {
		t.Fatal("Hash validation should fail")
	}
}

func TestVariant(t *testing.T) {
	_, _, err := CheckHash("pa$$word", "$argon2i$v=19$m=65536,t=1,p=2$mFe3kxhovyEByvwnUtr0ow$nU9AqnoPfzMOQhCHa9BDrQ+4bSfj69jgtvGu/2McCxU")
	if err != ErrIncompatibleVariant {
		t.Fatalf("expected error %s", ErrIncompatibleVariant)
	}
}
