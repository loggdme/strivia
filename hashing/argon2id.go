package hashing

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	strivia_random "github.com/loggdme/strivia/random"
	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash in returned by ComparePasswordAndHash if the provided
	// hash isn't in the expected format.
	ErrInvalidHash = errors.New("argon2id: hash is not in the correct format")

	// ErrIncompatibleVariant is returned by ComparePasswordAndHash if the
	// provided hash was created using a unsupported variant of Argon2.
	// Currently only argon2id is supported by this package.
	ErrIncompatibleVariant = errors.New("argon2id: incompatible variant of argon2")

	// ErrIncompatibleVersion is returned by ComparePasswordAndHash if the
	// provided hash was created using a different version of Argon2.
	ErrIncompatibleVersion = errors.New("argon2id: incompatible version of argon2")
)

// DefaultParamsOWASP provides some sane default parameters for hashing passwords based on
// the OWASP Argon2 recommendations with m=19456 (19 MiB), t=2, p=1, 128-bit salt, and 256-bit tag size.
//
// These default parameters should generally be used for development/testing purposes only. Custom parameters
// or the rfc defaults should be set/used for production applications depending on  available memory/CPU resources
// and business requirements.
var DefaultParamsOWASP = &Params{
	Memory:      19 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// DefaultParamsRFC1 provides some sane default parameters for hashing passwords based on the RFC 9106 Argon2
// first recommended option with m=2^(21) (2 GiB), t=1, p=4, 128-bit salt, and 256-bit tag size.
//
// These default parameters could be used for production applications. However you should validate
// that the parameters are appropriate for your application and environment.
var DefaultParamsRFC1 = &Params{
	Memory:      2 * 1024 * 1024,
	Iterations:  1,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// DefaultParamsRFC2 provides some sane default parameters for hashing passwords based on the RFC 9106 Argon2
// second recommended option with m=2^(16) (64 MiB), t=3, p=4, 128-bit salt, and 256-bit tag size.
//
// These default parameters could be used for production applications. However you should validate
// that the parameters are appropriate for your application and environment.
var DefaultParamsRFC2 = &Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// Params describes the input parameters used by the Argon2id algorithm. The
// Memory and Iterations parameters control the computational cost of hashing
// the password. The higher these figures are, the greater the cost of generating
// the hash and the longer the runtime. It also follows that the greater the cost
// will be for any attacker trying to guess the password. If the code is running
// on a machine with multiple cores, then you can decrease the runtime without
// reducing the cost by increasing the Parallelism parameter. This controls the
// number of threads that the work is spread across. Important note: Changing the
// value of the Parallelism parameter changes the hash output.
//
// For guidance and an outline process for choosing appropriate parameters see
// https://datatracker.ietf.org/doc/rfc9106 or https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
type Params struct {
	// The amount of memory used by the algorithm (in kibibytes).
	Memory uint32 `json:"m"`

	// The number of iterations over the memory.
	Iterations uint32 `json:"t"`

	// The number of threads (or lanes) used by the algorithm.
	Parallelism uint8 `json:"p"`

	// Length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32 `json:"s"`

	// Length of the generated key. 32 bytes or more is recommended.
	KeyLength uint32 `json:"k"`
}

// CreateHash returns an Argon2id hash of a plain-text password using the
// provided algorithm parameters. The returned hash follows the format used by
// the Argon2 reference C implementation and contains the base64-encoded Argon2id
// derived key prefixed by the salt and parameters. It looks like this:
//
// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
func CreateHash[T interface{ string | []byte }](password T, params *Params) (hash string) {
	salt := strivia_random.SecureRandomBytes(params.SaltLength)

	key := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Key)
	return hash
}

// ComparePasswordAndHash performs a constant-time comparison between a plain-text password and Argon2id hash,
// using the parameters and salt contained in the hash. It returns true if they match, otherwise it returns false.
func ComparePasswordAndHash[T interface{ string | []byte }](password T, hash string) (match bool, err error) {
	match, _, err = CheckHash(password, hash)
	return match, err
}

// CheckHash is like ComparePasswordAndHash, except it also returns the params that the hash was created with.
// This can be useful if you want to update your hash params over time.
func CheckHash[T interface{ string | []byte }](password T, hash string) (match bool, params *Params, err error) {
	params, salt, key, err := DecodeHash(hash)
	if err != nil {
		return false, nil, err
	}

	otherKey := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, params, nil
	}

	return false, params, nil
}

// DecodeHash expects a hash created from this package, and parses it to return the params used to
// create it, as well as the salt and key (password hash).
func DecodeHash(hash string) (params *Params, salt, key []byte, err error) {
	r := strings.NewReader(hash)

	_, err = fmt.Fscanf(r, "$argon2id$")
	if err != nil {
		return nil, nil, nil, ErrIncompatibleVariant
	}

	var version int
	_, err = fmt.Fscanf(r, "v=%d$", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &Params{}
	_, err = fmt.Fscanf(r, "m=%d,t=%d,p=%d$", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, nil, err
	}
	if bytes.ContainsAny(rest, "\r\n") {
		return nil, nil, nil, ErrInvalidHash
	}

	var i int
	if i = bytes.IndexByte(rest, '$'); i == -1 {
		return nil, nil, nil, ErrInvalidHash
	}

	b64Enc := base64.RawStdEncoding.Strict()

	salt = make([]byte, b64Enc.DecodedLen(i))
	_, err = b64Enc.Decode(salt, rest[:i])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	key = make([]byte, b64Enc.DecodedLen(len(rest)-i-1))
	_, err = b64Enc.Decode(key, rest[i+1:])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(key))

	return params, salt, key, nil
}
