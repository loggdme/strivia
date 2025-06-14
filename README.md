# 🔐 Strivia Auth Go

Strivia Auth is a highly opinionated toolset for building your own authentication and authorization flows in Go. It provides modular, composable primitives for modern auth, including OAuth, JWT, password hashing, OTP, and more. Inspired by [Lucia Auth](https://lucia-auth.com/), Strivia Auth is designed for developers who want full control over their authentication stack without vendor lock-in.

> Strivia Auth is **not** a general-purpose authentication library and never will be. It is intentionally opinionated to enforce secure, modern best practices for custom authentication implementations. For example, the JWT implementation always verifies all claims (including optional ones) and only supports Ed25519 for signing and verification. Many design decisions are made to prioritize security and composability over flexibility or legacy compatibility. If you need a more generic or configurable solution, this library may not be suitable for your use case.

## ✨ Features

- **OAuth 2.0 Providers**: Google, GitHub, Discord, Apple, Reddit, TikTok (easy to extend)
- **JWT**: Token creation, validation, and parsing (Ed25519)
- **Password Hashing**: Argon2id integration
- **Password Strength Validation**: Enforce strong password policies
- **OTP**: TOTP/HOTP for 2FA
- **Random Utilities**: Secure random string and state generation
- **No Database or Framework Lock-in**: Use with any storage or web framework

## 📦 Installation

```sh
go get github.com/loggdme/strivia
```

## 🚀 Examples

See the `examples/` directory for runnable demos:
- `examples/oauth/_server.go` — OAuth Debug Callback Server
- `examples/oauth/../main.go` — Examples for all supported OAuth Clients
- `examples/argon2id/main.go` — Argon2id password hashing
- `examples/otp/main.go` — OTP usage
- `examples/jwt/main.go` — JWT Sign/Verify usage
- `examples/pwnd/main.go` — Check for pwnd passwords
- `examples/passwordvalidator/main.go` — Quickly estimate password strength

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Credits

This project is heavily inspired by some of the listed projects. Some of them even power a large quantity of code used in this repository. So make sure to check them out:

- [Lucia Auth](https://lucia-auth.com/)
- [Oslo Project](https://github.com/oslo-project)
- [pquerna/otp](https://github.com/pquerna/otp)
- [alexedwards/argon2id](https://github.com/alexedwards/argon2id)
- [wagslane/go-password-validator](https://github.com/wagslane/go-password-validator)
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt/tree/main)
