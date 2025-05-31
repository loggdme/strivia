package password

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	// ErrPwnedRequest is returned by CheckPassword if the request to the
	// Pwned Passwords API fails.
	ErrPwnedRequest = errors.New("pwnedpasswords: request failed")

	// ErrPwnedResponse is returned by CheckPassword if the response from the
	// Pwned Passwords API is invalid.
	ErrPwnedResponse = errors.New("pwnedpasswords: invalid response")

	// ErrPwnedHash is returned by CheckPassword if the hash is not in the
	// expected format.
	ErrPwnedHash = errors.New("pwnedpasswords: hash is not in the correct format")
)

// IsPwnedPassword checks if the given password has been pwned using the
// Pwned Passwords API. It returns the number of times the password has
// been pwned or an error if the request fails or the response is invalid.
func IsPwnedPassword[T interface{ string | []byte }](input T) (int64, error) {
	h := sha1.New()
	h.Write([]byte(input))

	pwdhash := fmt.Sprintf("%X", h.Sum(nil))
	frange, lrange := pwdhash[0:5], pwdhash[5:40]

	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + frange)
	if err != nil {
		return -1, ErrPwnedRequest
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, ErrPwnedResponse
	}

	pwnedHashes := strings.Split(string(bodyBytes), "\r\n")

	var amountPwned int64
	for _, resp := range pwnedHashes {
		str_array := strings.Split(resp, ":")
		test := str_array[0]

		count, err := strconv.ParseInt(str_array[1], 0, 32)
		if err != nil {
			return -1, ErrPwnedHash
		}

		if test == lrange {
			amountPwned = count
			break
		}
	}

	return amountPwned, nil
}
