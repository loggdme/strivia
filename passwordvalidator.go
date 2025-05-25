package strivia

import (
	"math"
	"strings"
)

const (
	replaceChars      = `!@$&*`
	sepChars          = `_-., `
	otherSpecialChars = `"#%'()+/:;<=>?[\]^{|}~`
	lowerChars        = `abcdefghijklmnopqrstuvwxyz`
	upperChars        = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
	digitsChars       = `0123456789`
)

const (
	seqNumbers   = "0123456789"
	seqKeyboard0 = "qwertyuiop"
	seqKeyboard1 = "qwertzuiop"
	seqKeyboard2 = "asdfghjkl"
	seqKeyboard3 = "zxcvbnm"
	seqAlphabet  = "abcdefghijklmnopqrstuvwxyz"
)

// ValidatePasswordStrength checks if the password meets the minimum entropy requirement. It returns true if
// the password is strong enough, false otherwise.
//
// The entropy is calculated based on the number of unique characters in the password
// and the length of the password. The minimum entropy is specified in bits.
//
// An Entropy Threshold of 60 seems reasonable, as it would take in average 3.7 million years
// to guess the password while brute forcing 10.000 passwords per second.
//
// Look at the documentation of the @GetPasswordEntropy function to learn more about how the entropy is calculated.
func ValidatePasswordStrength(password string, minEntropy float64) bool {
	return GetPasswordEntropy(password) >= minEntropy
}

// GetPasswordEntropy returns the entropy in bits for the given password. The entropy is calculated like this:
//
//   - Determine the base number. The base is a sum of the different "character sets" found in the password.
//     For example you could use the following character sets. Using at least one character from each set your base number
//     will be 94: 26+26+10+5+5+22 = 94. Every unique character that doesn't match one of those sets will add 1 to the base.
//   - These are the character sets: 26 lowercase letters, 26 uppercase letters, 10 digits, 5 replacement characters - !@$&*,
//     5 separator characters - _-., , and 22 less common special characters - "#%'()+/:;<=>?[\]^{|}~
//   - After calculating the base, the total number of brute-force-guesses is found using the following formulae: base^length
//   - To report less entropy rather than more, additional steps are taken to calculate the length
//   - Repeated characters like aaaaaaaaaaaaa, or 111222, the length of the sequence is modified to count as no more than 2
//   - Common sequences of length three or greater count as length 2 (e.g. 0123456789). The sequences are checked from back->front and front->back
//   - With the number of guesses it would take, the actual entropy in bits can be calculated using log2(guesses)
func GetPasswordEntropy(password string) float64 {
	base := getBase(password)
	length := getLength(password)
	return logPow(float64(base), length, 2)
}

// logPow calculates the logarithm of a number raised to a power.
// It uses the formula: log2(base^exp) = exp * log2(base).
func logPow(expBase float64, pow int, logBase float64) float64 {
	total := 0.0
	for range pow {
		total += logX(logBase, expBase)
	}
	return total
}

// logX calculates the logarithm of n to the base of base.
// It uses the formula: log2(n) = log2(n) / log2(base).
// If base is 0, it returns 0.
func logX(base, n float64) float64 {
	if base == 0 {
		return 0
	}
	return math.Log2(n) / math.Log2(base)
}

// getBase calculates the base for the password entropy calculation.
// It counts the number of unique characters in the password and adds the size of the character sets used.
func getBase(password string) int {
	chars := map[rune]struct{}{}
	for _, c := range password {
		chars[c] = struct{}{}
	}

	hasReplace := false
	hasSep := false
	hasOtherSpecial := false
	hasLower := false
	hasUpper := false
	hasDigits := false
	base := 0

	for c := range chars {
		switch {
		case strings.ContainsRune(replaceChars, c):
			hasReplace = true
		case strings.ContainsRune(sepChars, c):
			hasSep = true
		case strings.ContainsRune(otherSpecialChars, c):
			hasOtherSpecial = true
		case strings.ContainsRune(lowerChars, c):
			hasLower = true
		case strings.ContainsRune(upperChars, c):
			hasUpper = true
		case strings.ContainsRune(digitsChars, c):
			hasDigits = true
		default:
			base++
		}
	}

	if hasReplace {
		base += len(replaceChars)
	}
	if hasSep {
		base += len(sepChars)
	}
	if hasOtherSpecial {
		base += len(otherSpecialChars)
	}
	if hasLower {
		base += len(lowerChars)
	}
	if hasUpper {
		base += len(upperChars)
	}
	if hasDigits {
		base += len(digitsChars)
	}

	return base
}

// getLength calculates the length of the password for the entropy calculation.
// It removes more than two repeating characters and more than two characters from common sequences.
// The sequences are checked from back->front and front->back.
func getLength(password string) int {
	password = removeMoreThanTwoRepeatingChars(password)

	password = removeMoreThanTwoFromSequence(password, seqNumbers)
	password = removeMoreThanTwoFromSequence(password, seqKeyboard0)
	password = removeMoreThanTwoFromSequence(password, seqKeyboard1)
	password = removeMoreThanTwoFromSequence(password, seqKeyboard2)
	password = removeMoreThanTwoFromSequence(password, seqKeyboard3)
	password = removeMoreThanTwoFromSequence(password, seqAlphabet)

	password = removeMoreThanTwoFromSequence(password, getReversedString(seqNumbers))
	password = removeMoreThanTwoFromSequence(password, getReversedString(seqKeyboard0))
	password = removeMoreThanTwoFromSequence(password, getReversedString(seqKeyboard1))
	password = removeMoreThanTwoFromSequence(password, getReversedString(seqKeyboard2))
	password = removeMoreThanTwoFromSequence(password, getReversedString(seqKeyboard3))
	password = removeMoreThanTwoFromSequence(password, getReversedString(seqAlphabet))

	return len(password)
}

// removeMoreThanTwoFromSequence removes characters from the password that are part of a sequence
// if they appear more than twice in a row. It returns the modified password.
func removeMoreThanTwoFromSequence(s string, seq string) string {
	runes, seqRunes, matches := []rune(s), []rune(seq), 0

	for i := 0; i < len(runes); i++ {
		for j := range seqRunes {
			if i >= len(runes) {
				break
			}

			if runes[i] != seqRunes[j] {
				matches = 0
				continue
			}

			matches += 1

			if matches > 2 {
				runes[i] = 0
			}

			i += 1
		}
	}

	result := make([]rune, 0, len(runes))
	for _, r := range runes {
		if r != 0 {
			result = append(result, r)
		}
	}

	return string(result)
}

// getReversedString returns the reversed string of the input string.
// It converts the string to a slice of runes, reverses the order of the runes,
// and then converts it back to a string.
func getReversedString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// removeMoreThanTwoRepeatingChars returns a copy of the input string s with any sequence of
// more than two consecutive repeating characters reduced to exactly two consecutive characters.
func removeMoreThanTwoRepeatingChars(s string) string {
	if len(s) < 3 {
		return s
	}

	runes := []rune(s)
	result := make([]rune, 0, len(runes))

	for i := range runes {
		r := runes[i]
		if len(result) >= 2 && r == result[len(result)-1] && r == result[len(result)-2] {
			continue
		}
		result = append(result, r)
	}

	return string(result)
}
