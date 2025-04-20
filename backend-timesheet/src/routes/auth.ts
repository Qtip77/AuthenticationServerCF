import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { hashPassword, comparePassword, generateToken, generateResetToken } from '../utils/auth';
import { authenticate } from '../middleware/auth';

// Define env type for route context
interface RouteEnv {
  DB: D1Database;
}

// Create the auth router
const authRouter = new Hono<{ Bindings: RouteEnv }>();

// Schema for user registration
const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  role: z.enum(['admin', 'manager', 'employee']).default('employee')
});

// Schema for user login
const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
});

// Schema for password reset request
const resetRequestSchema = z.object({
  email: z.string().email('Invalid email address')
});

// Schema for password reset
const resetPasswordSchema = z.object({
  token: z.string(),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

// Register a new user
authRouter.post('/register', zValidator('json', registerSchema), async (c) => {
  try {
    const { name, email, password, role } = c.req.valid('json');
    
    // Check if email already exists
    const existingUser = await c.env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (existingUser) {
      return c.json({ success: false, error: 'Email already in use' }, 409);
    }
    
    // Hash the password
    const hashedPassword = await hashPassword(password);
    
    // Insert the new user
    const result = await c.env.DB.prepare(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?) RETURNING id'
    ).bind(name, email, hashedPassword, role).first<{ id: number }>();
    
    if (!result) {
      return c.json({ success: false, error: 'Failed to create user' }, 500);
    }
    
    // Get the new user
    const newUser = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at FROM users WHERE id = ?'
    ).bind(result.id).first();
    
    return c.json({ success: true, data: newUser }, 201);
  } catch (error) {
    console.error('Registration error:', error);
    return c.json({ success: false, error: 'Registration failed' }, 500);
  }
});

// Login user
authRouter.post('/login', zValidator('json', loginSchema), async (c) => {
  try {
    const { email, password } = c.req.valid('json');
    
    // Find the user
    const user = await c.env.DB.prepare(
      'SELECT id, name, email, password, role FROM users WHERE email = ?'
    ).bind(email).first<{ id: number, name: string, email: string, password: string, role: string }>();
    
    if (!user) {
      return c.json({ success: false, error: 'Invalid email or password' }, 401);
    }
    
    // Check if password matches
    const isMatch = await comparePassword(password, user.password);
    
    if (!isMatch) {
      return c.json({ success: false, error: 'Invalid email or password' }, 401);
    }
    
    // Generate JWT
    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    });
    
    return c.json({
      success: true,
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return c.json({ success: false, error: 'Login failed' }, 500);
  }
});

// Logout - client-side implementation, just return success
authRouter.post('/logout', authenticate, (c) => {
  return c.json({ success: true, message: 'Logged out successfully' });
});

// Request password reset
authRouter.post('/reset', zValidator('json', resetRequestSchema), async (c) => {
  try {
    const { email } = c.req.valid('json');
    
    // Find the user
    const user = await c.env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first<{ id: number }>();
    
    if (user) {
      // Generate a reset token
      const token = generateResetToken();
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1); // Token valid for 1 hour
      
      // Delete any existing tokens for this user
      await c.env.DB.prepare(
        'DELETE FROM password_reset_tokens WHERE user_id = ?'
      ).bind(user.id).run();
      
      // Store the token
      await c.env.DB.prepare(
        'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
      ).bind(user.id, token, expiresAt.toISOString()).run();
      
      // In a real app, send an email with the reset link
      console.log(`Reset token for ${email}: ${token}`);
    }
    
    // Always return success to prevent email enumeration
    return c.json({
      success: true,
      message: 'If your email exists in our system, you will receive a password reset link'
    });
  } catch (error) {
    console.error('Password reset request error:', error);
    return c.json({ success: false, error: 'Password reset request failed' }, 500);
  }
});

// Process password reset
authRouter.post('/reset/confirm', zValidator('json', resetPasswordSchema), async (c) => {
  try {
    const { token, password } = c.req.valid('json');
    
    // Find the token and check if it's valid
    const resetToken = await c.env.DB.prepare(`
      SELECT user_id FROM password_reset_tokens 
      WHERE token = ? AND expires_at > datetime('now')
    `).bind(token).first<{ user_id: number }>();
    
    if (!resetToken) {
      return c.json({ success: false, error: 'Invalid or expired token' }, 400);
    }
    
    // Hash the new password
    const hashedPassword = await hashPassword(password);
    
    // Update the user's password
    await c.env.DB.prepare(
      'UPDATE users SET password = ? WHERE id = ?'
    ).bind(hashedPassword, resetToken.user_id).run();
    
    // Delete the used token
    await c.env.DB.prepare(
      'DELETE FROM password_reset_tokens WHERE token = ?'
    ).bind(token).run();
    
    return c.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password reset confirmation error:', error);
    return c.json({ success: false, error: 'Password reset failed' }, 500);
  }
});

export default authRouter; 