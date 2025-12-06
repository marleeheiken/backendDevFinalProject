# backendDevFinalProject

# Assignment #6: Course Database Assignment

A simple course catalog management API built with Express.js and SQLite.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create database and tables:
   ```bash
   node database/setup.js
   ```

3. Seed database with sample data:
   ```bash
   node database/seed.js
   ```

4. Start the server:
   ```bash
   npm start
   ```

## API Endpoints

- `POST /api/register` - Registers a new user (RD or RA)
- `POST /api/login` - Logs in a user and returns a JWT token
  
- `GET /api/users` - Get all user accounts (RD Access Only)
- `GET /api/users/:id` - Get user account by ID (RD Access Only)
- `PUT /api/users/:id` - Update user account by ID (RD Access Only)
- `DELETE /api/users/:id` - Delete user account by ID (RD Access Only, prevents self-deletion)

- `GET /api/residents` - Get all resident records (Scoped access for RAs)
- `GET /api/residents/:id` - Get resident record by ID
- `POST /api/residents` - Create a new resident record (RD Access Only)
- `PUT /api/residents/:id` - Update resident record by ID (RD Access Only)
- `DELETE /api/residents/:id` - Delete resident record by ID (RD Access Only)

- `GET /api/incidents` - Get all incident reports (Scoped access for RAs)
- `GET /api/incidents/:id` - Get incident report by ID (Scoped access for RAs)
- `POST /api/incidents` - Create a new incident report
- `PUT /api/incidents/:id` - Update incident report by ID (Scoped access for RAs)
- `DELETE /api/incidents/:id` - Delete incident report by ID (Scoped access for RAs)

## File Structure

```
server.js
database/
├── setup.js
├── seed.js
└── university.db
package.json
README.md
```
