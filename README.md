# Secure Authentication Web Application

## Objective
The objective of this project is to design and implement a simple web-based
authentication system with a strong emphasis on security best practices.

## Scope
This application focuses on core authentication features such as user sign-up,
login, session management, and logout. Advanced features are intentionally
excluded to keep the security model simple and auditable.

## Threat Model
- SQL Injection → Prevented using parameterized queries
- Cross-Site Scripting (XSS) → Prevented using output escaping and CSP
- CSRF → Prevented using CSRF tokens
- Brute-force login attempts → Mitigated using rate limiting
- Password compromise → Prevented using strong hashing (bcrypt)

## Technology Choice
Node.js with Express is used for its simplicity and wide adoption.
SQLite is used as a lightweight database for local development.
