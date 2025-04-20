import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { cors } from 'hono/cors';

// Import routes
import authRouter from './routes/auth';
import usersRouter from './routes/users';
import adminRouter from './routes/admin';
import rolesRouter from './routes/roles';

// Define the environment interface
interface Env {
  DB: D1Database;
}

// Create the main app
const app = new Hono<{ Bindings: Env }>();

// Apply CORS middleware
app.use('/*', cors());

// Create SQL for schema initialization
const SCHEMA_SQL = `
-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT CHECK(role IN ('admin', 'manager', 'employee')) NOT NULL DEFAULT 'employee',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Trigger to update the updated_at timestamp
CREATE TRIGGER IF NOT EXISTS users_updated_at
AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for token lookup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
`;

// Initialization middleware - runs on first request
app.use('/*', async (c, next) => {
  try {
    // Setup database schema
    await c.env.DB.exec(SCHEMA_SQL);
    
    // Check if we need to add sample data
    const result = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM users'
    ).first<{ count: number }>();
    
    const count = result?.count || 0;
    
    // Add sample users if the table is empty
    if (count === 0) {
      // Import auth utils for password hashing
      const { hashPassword } = await import('./utils/auth');
      
      const sampleUsers = [
        { 
          name: 'Admin User', 
          email: 'admin@example.com', 
          password: await hashPassword('Password123!'), 
          role: 'admin' 
        },
        { 
          name: 'Manager User', 
          email: 'manager@example.com', 
          password: await hashPassword('Password123!'), 
          role: 'manager' 
        },
        { 
          name: 'Employee User', 
          email: 'employee@example.com', 
          password: await hashPassword('Password123!'), 
          role: 'employee' 
        }
      ];
      
      for (const user of sampleUsers) {
        await c.env.DB.prepare(
          'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)'
        ).bind(user.name, user.email, user.password, user.role).run();
      }
      
      console.log('Added sample users to database');
    }
  } catch (error) {
    console.error('Database setup error:', error);
  }
  await next();
});

// Mount API routes
app.route('/api/auth', authRouter);
app.route('/api/users', usersRouter);
app.route('/api/admin', adminRouter);
app.route('/api/roles', rolesRouter);

// Legacy routes for read-only operations
app.get('/users', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at, updated_at FROM users ORDER BY created_at DESC'
    ).all();
    
    return c.json({ success: true, data: results });
  } catch (error) {
    console.error('Error fetching users:', error);
    return c.json({ success: false, error: 'Failed to fetch users' }, 500);
  }
});

app.get('/users/:id', async (c) => {
  const id = c.req.param('id');
  
  try {
    const user = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?'
    ).bind(id).first();
    
    if (!user) {
      return c.json({ success: false, error: 'User not found' }, 404);
    }
    
    return c.json({ success: true, data: user });
  } catch (error) {
    console.error(`Error fetching user ${id}:`, error);
    return c.json({ success: false, error: 'Failed to fetch user' }, 500);
  }
});

// Health check endpoint
app.get('/health', (c) => c.json({ status: 'ok' }));

// Export the application
export default app;
