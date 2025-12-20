package email

import (
	"strings"
	"testing"
)

func TestVerifyEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		// Valid emails
		{
			name:  "valid simple email",
			email: "test@example.com",
			want:  true,
		},
		{
			name:  "valid email with subdomain",
			email: "user@mail.example.com",
			want:  true,
		},
		{
			name:  "valid email with plus",
			email: "user+tag@example.com",
			want:  true,
		},
		{
			name:  "valid email with dots in local part",
			email: "first.last@example.com",
			want:  true,
		},
		{
			name:  "valid email with numbers",
			email: "user123@example456.com",
			want:  true,
		},
		{
			name:  "valid email with hyphen in domain",
			email: "user@my-domain.com",
			want:  true,
		},
		{
			name:  "valid email at max length (255 chars)",
			email: strings.Repeat("a", 243) + "@example.com",
			want:  true,
		},

		// Invalid emails - too long
		{
			name:  "invalid email exceeding 255 characters",
			email: strings.Repeat("a", 244) + "@example.com",
			want:  false,
		},

		// Invalid emails - whitespace
		{
			name:  "invalid email starting with whitespace",
			email: " test@example.com",
			want:  false,
		},
		{
			name:  "invalid email ending with whitespace",
			email: "test@example.com ",
			want:  false,
		},

		// Invalid emails - missing @ or .
		{
			name:  "invalid email without @",
			email: "testexample.com",
			want:  false,
		},
		{
			name:  "invalid email without .",
			email: "test@examplecom",
			want:  false,
		},
		{
			name:  "invalid email without @ and .",
			email: "testexamplecom",
			want:  false,
		},

		// Invalid emails - empty parts
		{
			name:  "invalid email starting with @",
			email: "@example.com",
			want:  false,
		},
		{
			name:  "invalid email starting with .",
			email: ".test@example.com",
			want:  false,
		},
		{
			name:  "invalid email ending with @",
			email: "test@",
			want:  false,
		},
		{
			name:  "invalid email ending with .",
			email: "test@example.",
			want:  false,
		},

		// Invalid emails - @ and . position issues
		{
			name:  "invalid email with @ immediately before .",
			email: "test@.com",
			want:  false,
		},
		{
			name:  "invalid email with . immediately after @",
			email: "test@.example",
			want:  false,
		},
		{
			name:  "invalid email with . before @",
			email: "test.@example",
			want:  false,
		},

		// Edge cases
		// Note: Empty string causes panic - see TestVerifyEmail_PanicsOnEmptyString
		{
			name:  "invalid single character",
			email: "a",
			want:  false,
		},
		{
			name:  "invalid only @",
			email: "@",
			want:  false,
		},
		{
			name:  "invalid only .",
			email: ".",
			want:  false,
		},
		{
			name:  "invalid @ and . only",
			email: "@.",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyEmail(tt.email)
			if got != tt.want {
				t.Errorf("VerifyEmail(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}
