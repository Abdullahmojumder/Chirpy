**Chirpy**

Chirpy is a lightweight, modern microblogging platform built with Go, designed for simplicity and extensibility. It empowers users to create, share, and manage short posts ("chirps") while offering premium features through a subscription model powered by Polka webhooks.

**What Chirpy Does**
Chirpy provides a streamlined microblogging experience with the following core features:

- User Management: Secure registration, login, and profile updates with JWT authentication and refresh tokens.
- Chirp CRUD: Create, read, update, and delete chirps (up to 140 characters), with profanity filtering for clean content.
- Chirpy Red Membership: A premium tier unlocked via Polka webhooks, enabling advanced features like chirp editing (future-ready).
- Flexible API: Retrieve chirps with optional filtering by author_id and sorting by created_at (asc or desc).
- Webhook Security: API key validation ensures only Polka can upgrade users to Chirpy Red.
- Built on PostgreSQL with sqlc for type-safe queries and goose for migrations, Chirpy is robust, scalable, and developer-friendly.

**Why You Should Care**
Chirpy is more than just a microblogging toy—it’s a foundation for real-world applications:

- For Developers: Learn Go best practices, RESTful API design, authentication, and third-party webhook integration in a compact, production-ready codebase.
- For Businesses: Deploy a customizable platform for community engagement or internal messaging, with a monetizable premium tier.
- For Enthusiasts: Experiment with a fun, extensible project that’s easy to run and tweak—perfect for portfolios or side hustles.
Whether you’re building skills, prototyping a product, or just exploring, Chirpy delivers a polished starting point with room to grow.

**Getting Started**
* _Clone the Repo:_

git clone https://github.com/Abdullahmojumder/chirpy.git

cd chirpy

* _Set Up Environment:_

Copy .env.example to .env and fill in:

DB_URL: PostgreSQL connection string

TOKEN_SECRET: JWT secret key

POLKA_KEY: Polka API key (e.g., f271c81ff7084ee5b99a5091b42d486e)

PLATFORM: Set to dev for testing


* _Run Migrations:_

goose -dir sql/schema postgres "$DB_URL" up

* _Generate Queries:_

sqlc generate

* _Start the Server:_

go run main.go

Access at http://localhost:8080.

**API Highlights**

* POST /api/users: Register a new user.

* POST /api/chirps: Create a chirp (authenticated).

* GET /api/chirps: List chirps (?author_id=<uuid>&sort=asc|desc).

* POST /api/polka/webhooks: Upgrade users to Chirpy Red (Polka only).

* DELETE /api/chirps/{chirpID}: Delete a chirp (owner only).


**Contributing**
Feel free to fork, tweak, and submit PRs! Issues and feature requests are welcome on the GitHub Issues page.

**License**
MIT © Abdullahmojumder

