# Chirpy

Chirpy is a RESTful API service that allows users to create, read, and manage short messages called "chirps". It includes features like user authentication, refresh tokens, and a premium tier system.

## Prerequisites

- Go 1.21 or later
- PostgreSQL database
- Environment variables configured (see Configuration section)

## Setup

1. Clone the repository:
```bash
git clone https://github.com/jasonwashburn/chirpy.git
cd chirpy
```

2. Install dependencies:
```bash
go mod download
```

3. Create a `.env` file in the root directory with the following variables:
```env
DB_URL=postgres://username:password@localhost:5432/chirpy?sslmode=disable
TOKEN_SECRET=your-secret-key
POLKA_KEY=your-polka-key
```

4. Create the database:
```bash
createdb chirpy
```

5. Run the application:
```bash
go run main.go
```

The server will start on port 8080.

## API Documentation

### Authentication

#### Create User
- **POST** `/api/users`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**: User object with ID, email, and tokens

#### Login
- **POST** `/api/login`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**: User object with access token and refresh token

#### Refresh Token
- **POST** `/api/refresh`
- **Headers**: `Authorization: Bearer <refresh_token>`
- **Response**: New access token

#### Revoke Refresh Token
- **POST** `/api/revoke`
- **Headers**: `Authorization: Bearer <refresh_token>`
- **Response**: 204 No Content

### Chirps

#### Create Chirp
- **POST** `/api/chirps`
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "body": "Your chirp message"
  }
  ```
- **Response**: Created chirp object

#### Get All Chirps
- **GET** `/api/chirps`
- **Query Parameters**:
  - `sort`: `asc` or `desc` (default: `asc`)
  - `author_id`: Filter by user ID
- **Response**: Array of chirp objects

#### Get Chirp by ID
- **GET** `/api/chirps/{chirp_id}`
- **Response**: Single chirp object

#### Delete Chirp
- **DELETE** `/api/chirps/{chirp_id}`
- **Headers**: `Authorization: Bearer <access_token>`
- **Response**: 204 No Content

### User Management

#### Update User
- **PUT** `/api/users`
- **Headers**: `Authorization: Bearer <access_token>`
- **Body**:
  ```json
  {
    "email": "newemail@example.com",
    "password": "newpassword123"
  }
  ```
- **Response**: Updated user object

### Premium Features

#### Upgrade to Chirpy Red
- **POST** `/api/polka/webhooks`
- **Headers**: `Authorization: ApiKey <polka_key>`
- **Body**:
  ```json
  {
    "event": "user.upgraded",
    "data": {
      "user_id": "user-uuid"
    }
  }
  ```
- **Response**: 204 No Content

## Response Formats

### Chirp Object
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "body": "string",
  "user_id": "uuid"
}
```

### User Object
```json
{
  "id": "uuid",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "email": "string",
  "is_chirpy_red": boolean
}
```

## Error Responses

All error responses follow this format:
```json
{
  "error": "Error message"
}
```

Common HTTP status codes:
- 200: Success
- 201: Created
- 204: No Content
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Internal Server Error

## Development

### Running Tests
```bash
go test ./...
```

### Environment Variables

- `DB_URL`: PostgreSQL connection string
- `TOKEN_SECRET`: Secret key for JWT signing
- `POLKA_KEY`: API key for Polka webhook integration
- `PLATFORM`: Set to "dev" for development mode
