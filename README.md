<div align="center">

![Loggd Banner](./.github/assets/header.webp)
# Strivia Auth

</div>

<br>

A highly opinionated toolset for building your own authentication and authorization flows in Go. Strivia provides modular, composable primitives for modern auth-OAuth 2.0, JWT, password hashing, MFA, breach detection, and more-without database or framework lock-in. Inspired by [Lucia Auth](https://lucia-auth.com/), it is designed for developers who want full control over their authentication stack.

> Strivia is **not** a general-purpose authentication library. It is intentionally opinionated to enforce secure, modern best practices. For example, the JWT implementation always verifies all claims and only supports Ed25519 for signing and verification. Design decisions prioritize security and composability over flexibility or legacy compatibility. If you need a configurable or generic solution, this library may not suit your use case.
>
> For a comprehensive, security-first guide covering the concepts implemented in Strivia-password hashing with Argon2id, OAuth flows, JWT-based auth with access/refresh tokens, MFA, breach detection, and more-see the matching [Medium article](https://medium.com/@loggd/building-secure-authentication-a-complete-guide-to-jwts-passwords-mfa-and-oauth-fdad8d243b91).

## ✨ Features

| Package       | Description                                                                        |
|---------------|------------------------------------------------------------------------------------|
| **OAuth 2.0** | Google, GitHub, Discord, Apple, Twitch, TikTok with PKCE and Id Token validation   |
| **JWT**       | Token creation, validation, and parsing (Ed25519, RSA via JWKS)                    |
| **Password**  | Argon2id hashing, entropy-based strength validation, Have I Been Pwned integration |
| **OTP**       | TOTP/HOTP for 2FA, recovery codes, secret encryption (ChaCha20-Poly1305)           |
| **Email**     | Verification helpers and cryptographically secure random OTP codes                 |
| **Random**    | Secure random strings, bytes, and state generation                                 |

No database or framework lock-in-use with any storage or web framework.

## ⚙️ Prerequisites

Install all required tools at their tested versions using [mise](https://mise.jdx.dev/):

```bash
mise install
```

## 📦 Installation

```bash
go get github.com/loggdme/strivia
```

## 🚀 Usage

See the `examples/` directory for runnable demos:

| Example              | Description                          |
|----------------------|--------------------------------------|
| `argon2id/`          | Password hashing with Argon2id       |
| `email/`             | Email verification and OTP codes     |
| `jwt/`               | JWT signing and validation           |
| `jwks/`              | Fetching and using JSON Web Key Sets |
| `oauth/google/`      | Google OAuth 2.0 flow                |
| `oauth/github/`      | GitHub OAuth 2.0 flow                |
| `otp/`               | TOTP 2FA setup and verification      |
| `passwordvalidator/` | Password strength validation         |
| `pwnd/`              | Breach database checking (HIBP)      |

## 🧹 Development

Run tests and vet from the project root:

```bash
mise run go:test
mise run go:vet
```

Or without mise:

```bash
go test -race $(go list ./... | grep -v /examples/)
go vet ./...
```

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
