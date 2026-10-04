# FastAPI authentication backend

This small API provides account registration, login, logout, and current-user lookup. It uses SQLite by default, Argon2 password hashing, and signed bearer access tokens.

## Run locally

1. Create and activate a virtual environment, then install `requirements.txt`.
2. Copy `.env.example` to `.env` and replace `SECRET_KEY` with a private random value of at least 32 characters. Do not commit `.env`.
3. Start the API with `uvicorn main:app --reload`.
4. Open `/docs` on the local server to try the endpoints.

## Endpoints

- `POST /auth/register` — JSON: `{"email":"person@example.com","password":"a-long-unique-password"}`
- `POST /auth/login` — JSON email and password; returns an access token.
- `POST /auth/logout` — send `Authorization: Bearer <access_token>` to revoke the current token.
- `GET /auth/me` — returns the authenticated account.
Passwords must be 12–128 characters.

## Production notes

Use HTTPS, a strong secret stored in a secret manager, and a managed database. Add rate limiting to login, monitoring, and appropriate CORS settings for your frontend. The default SQLite setup is for development, not a multi-instance production deployment.
