# Armora-Backend

Backend API for Armora — a mobile security and scanning service. This Node.js (ESM) Express app exposes endpoints used by the mobile client to perform URL scans, Wi‑Fi analysis, device/system security checks, and AI-augmented analysis.

This README provides quickstart instructions, the environment variables required, a short overview of the project layout, and where to look for API/request shapes.

## Quick start (development)

Prerequisites
- Node.js 18+ (ESM modules enabled)
- npm

From the repository root (PowerShell):

```powershell
npm install
# run in dev with nodemon (script defined as "dev")
npm run dev
# or run directly with node
node server.js
```

Notes
- The project uses `type: "module"` in `package.json` (ES modules).
- The provided `dev` script runs `npx nodemon server.js`. There is no `start` script by default — you can run `node server.js` for a simple start.

## Required environment variables
- MONGO_URI — MongoDB connection string (required)
- JWT_SECRET — secret to sign JSON Web Tokens (required for auth flows)
- GEMINI_API_KEY — API key for Google Generative AI (if AI features are used)
- GSB_API_KEY — Google Safe Browsing API key (optional; used for URL safety checks)
- API_URL — used by `src/cron.js` to send periodic GET requests (optional)
- PORT — optional override for the server port (defaults to 3000)

Create a `.env` file in development with those keys (do not commit secrets).

## Project layout (high level)

```
./
  package.json
  server.js               # entry point — imports app and calls connectDB()
  PROJECT_DOCUMENTATION.txt
  README.md
  src/
    app.js                # express app, middleware, route mounting, starts cron
    cron.js               # scheduled job(s) (job.start() runs on app load)
    controllers/          # route handlers
    routes/               # express routers
    services/             # business logic, external API wrappers
    utils/                # helpers, scoring, caching
    db/                   # mongoose connection (connectDB)
    models/               # mongoose schemas (User)
```

## How to run in production
- Ensure environment variables are set (MONGO_URI, JWT_SECRET, GEMINI_API_KEY if needed).
- Use a process manager (PM2) or containerize with Docker.
- Replace the in-process cache/cron with external services (Redis, hosted scheduler) for multiple instances.

## Important endpoints (where to look)
- Auth: `/api/auth` (register/login) — see `src/routes/auth.route.js` and `src/controllers/auth.controller.js`
- Scan: `/api/scan` — site/URL scanning (`src/controllers/scan.controller.js`)
- Wi‑Fi: `/api/wifi-scan` — wifi analysis (`src/controllers/wifi.controller.js`)
- Security: `/api/security` — device/system security analysis (`src/controllers/security.controller.js`)
- AI: `/api/ai` and `/api/ai/chat` — AI analysis and chat (`src/controllers/ai.controller.js`, `src/services/ai.service.js`)

To understand exact request/response shapes, open the route and controller files mentioned above.

## Development notes & recommendations
- Move cache from in-memory to Redis for production multi-instance deployments.
- Add input validation middleware (e.g., express-validator or Joi) on public endpoints.
- Add structured logging (winston/pino) and centralized error handling middleware.
- Add tests (unit tests for utils, integration tests for routes/controllers).

## Contributing
- Fork the repo, create a feature branch, run tests (when present), open a pull request describing changes.

## License
Specify a license in `package.json` and add a `LICENSE` file if you want to open-source the project.

## Where to go next
- See `PROJECT_DOCUMENTATION.txt` for a thorough project overview, architecture notes, API contract suggestions, and deployment considerations.

