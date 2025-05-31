package otp

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestGenerateRandomOTP_Defaults(t *testing.T) {
	otp, err := GenerateRandomOTP(GenerateOptsRandomOTP{
		UserID:    "user",
		UserEmail: "user@loggd.me",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(otp.Code) != 6 {
		t.Errorf("expected code length 6, got %d", len(otp.Code))
	}
	if otp.ExpiresAt.Sub(time.Now()) < 14*time.Minute {
		t.Errorf("expected validity at least 14 minutes, got %v", otp.ExpiresAt.Sub(time.Now()))
	}
}

func TestGenerateRandomOTP_CustomOptions(t *testing.T) {
	opts := GenerateOptsRandomOTP{
		Length:    8,
		Validity:  30 * time.Minute,
		UserID:    "user",
		UserEmail: "user@loggd.me",
	}
	otp, err := GenerateRandomOTP(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(otp.Code) != 8 {
		t.Errorf("expected code length 8, got %d", len(otp.Code))
	}
	if otp.UserID != opts.UserID {
		t.Errorf("expected UserID %q, got %q", opts.UserID, otp.UserID)
	}
	if otp.UserEmail != opts.UserEmail {
		t.Errorf("expected UserEmail %q, got %q", opts.UserEmail, otp.UserEmail)
	}
	if otp.ExpiresAt.Sub(time.Now()) < 29*time.Minute {
		t.Errorf("expected validity at least 29 minutes, got %v", otp.ExpiresAt.Sub(time.Now()))
	}
}

func TestGenerateRandomOTP_AlphanumericCharacters(t *testing.T) {
	otp, err := GenerateRandomOTP(GenerateOptsRandomOTP{Length: 20, UserEmail: "user@loggd.me", UserID: "user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, r := range otp.Code {
		found := slices.Contains(AlphanumericCharacters, r)
		if !found {
			t.Errorf("character %q in code is not allowed", r)
		}
	}
}

func TestGenerateRandomOTP_UniqueCodes(t *testing.T) {
	codes := make(map[string]struct{})
	for range 10 {
		otp, err := GenerateRandomOTP(GenerateOptsRandomOTP{UserEmail: "user@loggd.me", UserID: "user"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, exists := codes[otp.Code]; exists {
			t.Errorf("duplicate code generated: %s", otp.Code)
		}
		codes[otp.Code] = struct{}{}
	}
}

func TestGenerateRandomOTP_MissingUserEmail(t *testing.T) {
	_, err := GenerateRandomOTP(GenerateOptsRandomOTP{UserID: "user"})
	if err == nil || err != ErrGenerateRandomOtpMissingUserEmail {
		t.Errorf("expected error for missing UserEmail, got %v", err)
	}
}

func TestGenerateRandomOTP_MissingUserID(t *testing.T) {
	_, err := GenerateRandomOTP(GenerateOptsRandomOTP{UserEmail: "user@loggd.me"})
	if err == nil || err != ErrGenerateRandomOtpMissingUserID {
		t.Errorf("expected error for missing UserID, got %v", err)
	}
}

func TestRandomOTPCode_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "valid OTP (expires in future)",
			expiresAt: now.Add(1 * time.Minute),
			want:      true,
		},
		{
			name:      "expired OTP (expires in past)",
			expiresAt: now.Add(-1 * time.Minute),
			want:      false,
		},
		{
			name:      "expires exactly now (should be invalid)",
			expiresAt: now,
			want:      false,
		},
	}

	for _, tt := range tests {
		otp := &RandomOTPCode{
			Code:      "ABCDEF",
			ExpiresAt: tt.expiresAt,
			UserID:    "user",
			UserEmail: "user@loggd.me",
		}
		got := otp.IsValid()
		if got != tt.want {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}

func TestRandomOTPCode_String(t *testing.T) {
	otp := &RandomOTPCode{
		Code:      "ABCDEFG",
		ExpiresAt: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		UserID:    "user",
		UserEmail: "user@loggd.me",
	}
	got := otp.String()

	var parsed RandomOTPCode
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("String() output is not valid JSON: %v", err)
	}
	if parsed.Code != otp.Code {
		t.Errorf("expected Code %q, got %q", otp.Code, parsed.Code)
	}
	if !parsed.ExpiresAt.Equal(otp.ExpiresAt) {
		t.Errorf("expected ExpiresAt %v, got %v", otp.ExpiresAt, parsed.ExpiresAt)
	}
	if parsed.UserID != otp.UserID {
		t.Errorf("expected UserID %q, got %q", otp.UserID, parsed.UserID)
	}
	if parsed.UserEmail != otp.UserEmail {
		t.Errorf("expected UserEmail %q, got %q", otp.UserEmail, parsed.UserEmail)
	}
}

func TestRandomOTPFromString_ValidInput(t *testing.T) {
	jsonStr := "{\"code\":\"ABCDEFG\",\"expires_at\":\"2024-06-01T12:00:00Z\",\"user_id\":\"user\",\"user_email\":\"user@loggd.me\"}"

	got, err := RandomOTPFromString(jsonStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.Code != "ABCDEFG" {
		t.Errorf("expected Code %q, got %q", "ABCDEFG", got.Code)
	}

	if !got.ExpiresAt.Equal(time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("expected ExpiresAt %s, got %v", "2024-06-01T12:00:00Z", got.ExpiresAt)
	}

	if got.UserID != "user" {
		t.Errorf("expected UserID %q, got %q", "user", got.UserID)
	}

	if got.UserEmail != "user@loggd.me" {
		t.Errorf("expected UserEmail %q, got %q", "user@loggd.me", got.UserEmail)
	}
}

func TestRandomOTPFromString_InvalidJSON(t *testing.T) {
	invalidJSON := `{"code": "ABC", "expires_at": "not-a-date", "user_id": "user", "user_email": "user@loggd.me"`
	_, err := RandomOTPFromString(invalidJSON)
	if err == nil || !errors.Is(err, ErrParseRandomOtpFromStringFormat) {
		t.Errorf("expected ErrParseRandomOtpFromStringFormat, got %v", err)
	}
}

func TestRandomOTPFromString_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "missing code",
			json: `{"expires_at":"2024-06-01T12:00:00Z","user_id":"user","user_email":"user@loggd.me"}`,
		},
		{
			name: "missing user_id",
			json: `{"code":"ABCDEFG","expires_at":"2024-06-01T12:00:00Z","user_email":"user@loggd.me"}`,
		},
		{
			name: "missing user_email",
			json: `{"code":"ABCDEFG","expires_at":"2024-06-01T12:00:00Z","user_id":"user"}`,
		},
		{
			name: "missing expires_at",
			json: `{"code":"ABCDEFG","user_id":"user","user_email":"user@loggd.me"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RandomOTPFromString(tt.json)
			if err == nil || !errors.Is(err, ErrParseRandomOtpFromStringValues) {
				t.Errorf("expected ErrParseRandomOtpFromStringValues, got %v", err)
			}
		})
	}
}
