# Heart Non Pro Account API

This is the server-side part of the Webflow site. It owns users, Argon2 password hashes,
opaque HttpOnly session cookies, avatar files, session history, and all permission checks.

## Local setup

1. Install Python 3.12 or newer.
2. In this directory, create and activate a virtual environment.
3. Install the dependencies with `python -m pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` and set the values for the environment where the API runs.
5. Load the environment variables using your deployment platform or shell.
6. Run `python seed_account.py`. Press Enter at the username prompt to use `D2N1K`, then enter the initial password only into the hidden prompts. It is immediately stored as an Argon2 hash and never written to the source code, shell command, or frontend.
7. Start the API with `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`.

For production, serve the API through HTTPS. Use `COOKIE_SECURE=true` and
`COOKIE_SAMESITE=none` when the Webflow site and API use different origins. Add only the
actual Webflow and custom-domain origins to `CORS_ORIGINS`; never use `*` with credentials.

## Webflow connection

Set `data-api-base` on the existing `<body>` element in `index.html` to the public HTTPS API
origin, for example `https://api.example.com`. Leave it empty only when the API is served from
the same origin as the page. The browser sends the session cookie with `credentials: include`.

## Location data

For approximate city/country detection, obtain the MaxMind GeoLite2 City database and point
`GEOLITE_CITY_DATABASE` to it. If the database is absent, the API displays no location rather
than inventing one. Configure `TRUSTED_PROXY_IPS` only for reverse proxies you control.

## Session behavior

Every authenticated request extends the server-side `last_seen_at` and expiry by seven days.
The browser cookie is persistent only when Remember Me was selected. Expired sessions are
removed server-side during authentication, login, and session-list requests.
