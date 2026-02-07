<img width="947" height="549" alt="image" src="https://github.com/user-attachments/assets/f625ab8d-4c93-48db-ae15-6a68884f80af" /><img width="947" height="549" alt="image" src="https://github.com/user-attachments/assets/941500a1-fe1f-48c8-a6e6-68ff48aaa614" /># Secure Authentication Web Application

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

## Security Features Implemented

- Passwords hashed using bcrypt
- Session-based authentication using express-session
- CSRF protection using CSRF tokens
- Brute-force attack mitigation using rate limiting
- Input validation and output escaping to prevent XSS
- Secure cookies with HttpOnly and SameSite flags


