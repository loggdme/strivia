package email

import "strings"

// VerifyEmail checks if the email is valid. This is a basic regex free email validation that checks for the following:
// - Contains at least one @ character and has at least one character before the @
// - The domain portion (after @) includes at least one . with characters before and after it
// - The local portion (before @) does not start or end with a dot
// - Does not start or end with whitespace
// - Maximum length of 255 characters
func VerifyEmail(email string) bool {
	// Email must not be empty or longer than 255 characters
	if len(email) == 0 || len(email) > 255 {
		return false
	}

	// Email must not start or end with whitespace
	if email[0] == ' ' || email[len(email)-1] == ' ' {
		return false
	}

	// Find the @ symbol (use LastIndex to get the domain separator)
	atIndex := strings.LastIndex(email, "@")

	// Email must contain at least one @ and have content before and after it
	if atIndex <= 0 || atIndex >= len(email)-1 {
		return false
	}

	// Split into local and domain parts
	localPart := email[:atIndex]
	domainPart := email[atIndex+1:]

	// Local part must not start or end with a dot
	if localPart[0] == '.' || localPart[len(localPart)-1] == '.' {
		return false
	}

	// Domain part must contain at least one dot
	dotIndex := strings.Index(domainPart, ".")
	if dotIndex == -1 {
		return false
	}

	// Domain must not start or end with a dot
	if domainPart[0] == '.' || domainPart[len(domainPart)-1] == '.' {
		return false
	}

	// Ensure there's at least one character between @ and first dot,
	// and at least one character after the last dot in the domain
	lastDotIndex := strings.LastIndex(domainPart, ".")
	if dotIndex == 0 || lastDotIndex == len(domainPart)-1 {
		return false
	}

	return true
}
