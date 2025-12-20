package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

var (
	ErrInvalidKey            = errors.New("jwt: key is invalid")
	ErrInvalidKeyType        = errors.New("jwt: key is of invalid type")
	ErrTokenMalformed        = errors.New("jwt: token is malformed")
	ErrTokenInvalidAlgorithm = errors.New("jwt: token has an invalid algorithm")
)

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

// MarshalJSON is an implementation of the json.RawMessage interface and serializes the UNIX epoch
// represented in NumericDate to a byte array, using the precision specified in TimePrecision.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	truncatedDate := date.Truncate(time.Second)

	// For very large timestamps, UnixNano would overflow an int64, but this
	// function requires nanosecond level precision, so we have to use the
	// following technique to get round the issue:
	//
	// 1. Take the normal unix timestamp to form the whole number part of the
	//    output,
	// 2. Take the result of the Nanosecond function, which returns the offset
	//    within the second of the particular unix time instance, to form the
	//    decimal part of the output
	// 3. Concatenate them to produce the final result
	seconds := strconv.FormatInt(truncatedDate.Unix(), 10)
	nanosecondsOffset := strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', 0, 64)

	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)

	return output, nil
}

// UnmarshalJSON is an implementation of the json.RawMessage interface and
// deserializes a [NumericDate] from a JSON representation, i.e. a
// [json.Number]. This number represents an UNIX epoch with either integer or
// non-integer seconds.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var number json.Number
	var f float64

	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericData: %w", err)
	}

	if f, err = number.Float64(); err != nil {
		return fmt.Errorf("could not convert json number value to float: %w", err)
	}

	round, frac := math.Modf(f)
	*date = NumericDate{time.Unix(int64(round), int64(frac*1e9)).Truncate(time.Second)}

	return nil
}

// Audience represents a list of strings that can be used to specify the audience for a JWT.
// It is typically used in the `aud` (Audience) claim of a JWT to indicate the intended recipients of the token.
// The audience can be a single string or an array of strings, allowing for flexibility in specifying
type Audience []string

func (aud *Audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*aud = Audience{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(b, &multiple); err != nil {
		return fmt.Errorf("could not parse Audience: %w", err)
	}

	*aud = multiple
	return nil
}

func (aud Audience) MarshalJSON() ([]byte, error) {
	if len(aud) == 0 {
		return json.Marshal(nil)
	}

	if len(aud) == 1 {
		return json.Marshal(aud[0])
	}

	return json.Marshal([]string(aud))
}

// _EncodeSegment encodes the given byte slice into a base64 URL-encoded string without padding.
// It is typically used for encoding segments of a JWT (JSON Web Token).
func _EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

// _DecodeSegment decodes a base64 URL-encoded string segment using the RawURLEncoding
// scheme. It returns the decoded bytes or an error if the input is not properly
// base64 URL-encoded.
func _DecodeSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(segment)
}
