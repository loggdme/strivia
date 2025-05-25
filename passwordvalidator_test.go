package strivia

import (
	"math"
	"testing"
)

/* Benchmarks */

func BenchmarkValidatePasswordStrength(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ValidatePasswordStrength("aGoo0dMi#oFChaR2", 80)
	}
}

/* Tests */

func TestGetBase(t *testing.T) {
	actual := getBase("abcd")
	expected := len(lowerChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("abcdA")
	expected = len(lowerChars) + len(upperChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("A")
	expected = len(upperChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("^_")
	expected = len(otherSpecialChars) + len(sepChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("^")
	expected = len(otherSpecialChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("!")
	expected = len(replaceChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("123")
	expected = len(digitsChars)
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getBase("123ü")
	expected = len(digitsChars) + 1
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

func TestLogPow(t *testing.T) {
	expected := math.Round(math.Log2(math.Pow(7, 8)))
	actual := math.Round(logPow(7, 8, 2))
	if actual != expected {
		t.Errorf("Expected %v, got %v", expected, actual)
	}

	expected = math.Round(math.Log2(math.Pow(10, 11)))
	actual = math.Round(logPow(10, 11, 2))
	if actual != expected {
		t.Errorf("Expected %v, got %v", expected, actual)
	}

	expected = math.Round(math.Log2(math.Pow(11, 17)))
	actual = math.Round(logPow(11, 17, 2))
	if actual != expected {
		t.Errorf("Expected %v, got %v", expected, actual)
	}

	expected = math.Round(math.Log10(math.Pow(13, 21)))
	actual = math.Round(logPow(13, 21, 10))
	if actual != expected {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func TestRemoveMoreThanTwoFromSequence(t *testing.T) {
	actual := removeMoreThanTwoFromSequence("12345678", "0123456789")
	expected := "12"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = removeMoreThanTwoFromSequence("abcqwertyabc", "qwertyuiop")
	expected = "abcqwabc"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = removeMoreThanTwoFromSequence("", "")
	expected = ""
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = removeMoreThanTwoFromSequence("", "12345")
	expected = ""
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

func TestGetReversedString(t *testing.T) {
	actual := getReversedString("abcd")
	expected := "dcba"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getReversedString("1234")
	expected = "4321"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

func TestRemoveRepeatingChars(t *testing.T) {
	actual := removeMoreThanTwoRepeatingChars("aaaa")
	expected := "aa"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = removeMoreThanTwoRepeatingChars("bbbbbbbaaaaaaaaa")
	expected = "bbaa"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = removeMoreThanTwoRepeatingChars("ab")
	expected = "ab"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = removeMoreThanTwoRepeatingChars("")
	expected = ""
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

func TestGetLength(t *testing.T) {
	actual := getLength("aaaa")
	expected := 2
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getLength("11112222")
	expected = 4
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getLength("aa123456")
	expected = 4
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getLength("876543")
	expected = 2
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getLength("qwerty123456z")
	expected = 5
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

func TestValidate(t *testing.T) {
	passwordIsValid := ValidatePasswordStrength("mypass", 50)
	if passwordIsValid {
		t.Errorf("Password should not be strong enough")
	}

	passwordIsValid = ValidatePasswordStrength("MYPASS", 50)
	if passwordIsValid {
		t.Errorf("Password should not be strong enough")
	}

	passwordIsValid = ValidatePasswordStrength("mypassword", 4)
	if !passwordIsValid {
		t.Errorf("Password should be strong enough")
	}

	passwordIsValid = ValidatePasswordStrength("aGoo0dMi#oFChaR2", 80)
	if !passwordIsValid {
		t.Errorf("Password should be strong enough")
	}

	passwordIsValid = ValidatePasswordStrength("123", 60)
	if passwordIsValid {
		t.Errorf("Password should not be strong enough")
	}
}
