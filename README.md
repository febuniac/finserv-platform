# FinServ Platform

Internal monorepo for FinServ Co's core banking and transaction platform.

## Architecture

```
├── src/
│   ├── api/          # REST API routes
│   ├── auth/         # Authentication & authorization
│   ├── models/       # Database models
│   ├── services/     # Business logic
│   ├── middleware/    # Express middleware
│   └── utils/        # Shared utilities
├── tests/            # Test suite
└── scripts/          # Deployment & maintenance scripts
```

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js
- **Database**: PostgreSQL with Prisma ORM
- **Cache**: Redis
- **Auth**: JWT + OAuth2
- **Queue**: Bull (Redis-backed)

## Getting Started

```bash
npm install
cp .env.example .env
npm run db:migrate
npm run dev
```

## Environment Variables

See `.env.example` for required configuration.

## Testing

```bash
npm test           # Run all tests
npm run test:unit  # Unit tests only
npm run test:e2e   # End-to-end tests
```

## Deployment

```bash
npm run build
npm run deploy:staging
npm run deploy:production
```
