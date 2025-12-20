# 🔐 Strivia Auth Go

Strivia Auth is a highly opinionated toolset for building your own authentication and authorization flows in Go. It provides modular, composable primitives for modern auth, including OAuth, JWT, password hashing, OTP, and more. Inspired by [Lucia Auth](https://lucia-auth.com/), Strivia Auth is designed for developers who want full control over their authentication stack without vendor lock-in.

> Strivia Auth is **not** a general-purpose authentication library and never will be. It is intentionally opinionated to enforce secure, modern best practices for custom authentication implementations. For example, the JWT implementation always verifies all claims (including optional ones) and only supports Ed25519 for signing and verification. Many design decisions are made to prioritize security and composability over flexibility or legacy compatibility. If you need a more generic or configurable solution, this library may not be suitable for your use case.

> You can read more on how to implement a secure auth layer using this package in the matching [medium article](https://medium.com/@loggd/building-secure-authentication-a-complete-guide-to-jwts-passwords-mfa-and-oauth-fdad8d243b91).

## ✨ Features

- **OAuth 2.0 Providers**: Google, GitHub, Discord, Apple, Reddit, TikTok (easy to extend)
- **JWT**: Token creation, validation, and parsing (Ed25519)
- **Password Hashing**: Argon2id integration
- **Password Strength Validation**: Enforce strong password policies
- **OTP**: TOTP/HOTP for 2FA
- **Random Utilities**: Secure random string and state generation
- **No Database or Framework Lock-in**: Use with any storage or web framework


## 📦 Getting started

```sh
go get github.com/loggdme/strivia
```

> 🚀 See the `examples/` directory for runnable demos for the specific packages.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
