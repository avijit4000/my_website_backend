# FastAPI authentication backend

This small API provides account registration, login, logout, and current-user lookup. It uses PostgreSQL, Argon2 password hashing, and signed bearer access tokens.

## Run locally

1. Install and start PostgreSQL, then create a database named `auth_db`.
2. Create and activate a virtual environment, then install `requirements.txt`.
3. Copy `.env.example` to `.env`. Set `DATABASE_URL` to your PostgreSQL connection string and replace `SECRET_KEY` with a private random value of at least 32 characters. Do not commit `.env`.
4. Start the API with `uvicorn main:app --reload`.
5. Open `/docs` on the local server to try the endpoints.

The connection URL uses SQLAlchemy's Psycopg 3 driver, for example:
`postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/auth_db`.

## Endpoints

- `POST /auth/register` — JSON: `{"email":"person@example.com","password":"a-long-unique-password"}`
- `POST /auth/login` — JSON email and password; returns an access token.
- `POST /auth/logout` — send `Authorization: Bearer <access_token>` to revoke the current token.
- `GET /auth/me` — returns the authenticated account.
Passwords must be 12–128 characters.

## Production notes

Use HTTPS, a strong secret stored in a secret manager, and a managed PostgreSQL database. Add rate limiting to login, monitoring, and appropriate CORS settings for your frontend.
