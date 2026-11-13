# devsecops-access-control — DineDesk API

Node.js + Express API with JWT authentication, role/permission checks, branch-level
authorization and environment-based secrets.

    npm install
    cp .env.example .env     # then put a real random JWT_SECRET (32+ chars) in .env
    npm run dev              # start
    npm test                 # 23 Jest + Supertest tests (no secret needed)

Demo users (all invented): see src/store.js. Every demo account uses the invented
password in `DEMO_PASSWORD`; only bcrypt hashes are stored in memory.
