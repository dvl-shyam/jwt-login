# JWT Utility Package

A Go package for generating, signing, and validating JSON Web Tokens (JWTs) with support for common claims.

## Features

- Generate JWTs with custom claims.
- Sign JWTs using HMAC secret keys.
- Validate and parse JWTs.
- Support for common JWT claims: `exp`, `iss`, `sub`, `aud`.
- Error handling for expired, invalid, or malformed tokens.

## Installation

```bash
go get -u github.com/golang-jwt/jwt/v5
