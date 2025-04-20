# User Management API with Cloudflare Workers and D1

A Cloudflare Worker application using Hono framework to provide a REST API for user management with Cloudflare D1 database.

## Features

- Create, read, update, and delete users
- Data validation using Zod
- Cloudflare D1 database integration
- CORS support

## Setup

### Prerequisites

- Node.js and npm installed
- Cloudflare account
- Wrangler CLI installed (`npm install -g wrangler`)

### Installation

1. Clone the repository
2. Install dependencies:
   ```
   npm install
   ```

### D1 Database Setup

1. Login to Cloudflare:
   ```
   npx wrangler login
   ```

2. Create a D1 database:
   ```
   npx wrangler d1 create user_management
   ```

3. Update the `wrangler.toml` file with the database details from the previous command.

4. Apply the database schema:
   ```
   npx wrangler d1 execute user_management --file=./schema.sql
   ```

### Development

Start the development server:
```
npm run dev
```

### Deployment

Deploy to Cloudflare Workers:
```
npm run deploy
```

## API Endpoints

### Health Check
- `GET /health` - Check API status

### Users
- `GET /users` - Get all users
- `GET /users/:id` - Get user by ID
- `POST /users` - Create a new user
- `PATCH /users/:id` - Update a user
- `DELETE /users/:id` - Delete a user

## Request & Response Examples

### Create User

Request:
```json
POST /users

{
  "name": "John Doe",
  "email": "john@example.com",
  "role": "employee"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "employee",
    "created_at": "2023-10-20T12:00:00.000Z",
    "updated_at": "2023-10-20T12:00:00.000Z"
  }
}
```

## Error Handling

All errors return a JSON response with the following structure:

```json
{
  "success": false,
  "error": "Error message"
}
```

## License

MIT

```txt
npm run cf-typegen
```

Pass the `CloudflareBindings` as generics when instantiation `Hono`:

```ts
// src/index.ts
const app = new Hono<{ Bindings: CloudflareBindings }>()
```
