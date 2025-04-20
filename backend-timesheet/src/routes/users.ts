import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authenticate } from '../middleware/auth';
import { hashPassword, comparePassword } from '../utils/auth';

// Define env type for route context
interface RouteEnv {
  DB: D1Database;
}

// Create the users router
const usersRouter = new Hono<{ Bindings: RouteEnv }>();

// Apply authentication to all routes
usersRouter.use('/*', authenticate);

// Schema for user profile update
const profileUpdateSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').optional(),
  email: z.string().email('Invalid email address').optional()
});

// Schema for password change
const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string().min(8, 'New password must be at least 8 characters')
});

// Get current user profile
usersRouter.get('/me', async (c) => {
  try {
    const user = c.get('user');
    
    // Get the user details from the database
    const userDetails = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?'
    ).bind(user.id).first();
    
    if (!userDetails) {
      return c.json({ success: false, error: 'User not found' }, 404);
    }
    
    return c.json({ success: true, data: userDetails });
  } catch (error) {
    console.error('Get profile error:', error);
    return c.json({ success: false, error: 'Failed to get profile' }, 500);
  }
});

// Update current user profile
usersRouter.put('/me', zValidator('json', profileUpdateSchema), async (c) => {
  try {
    const user = c.get('user');
    const updates = c.req.valid('json');
    
    // Generate dynamic update query based on provided fields
    const fields = Object.keys(updates).filter(key => 
      updates[key as keyof typeof updates] !== undefined
    );
    
    if (fields.length === 0) {
      return c.json({ success: false, error: 'No fields to update' }, 400);
    }
    
    // If email is being updated, check it's not already taken
    if (updates.email) {
      const emailCheck = await c.env.DB.prepare(
        'SELECT id FROM users WHERE email = ? AND id != ?'
      ).bind(updates.email, user.id).first();
      
      if (emailCheck) {
        return c.json({ success: false, error: 'Email already in use' }, 409);
      }
    }
    
    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const values = fields.map(field => updates[field as keyof typeof updates]);
    
    // Update the user
    await c.env.DB.prepare(
      `UPDATE users SET ${setClause} WHERE id = ?`
    ).bind(...values, user.id).run();
    
    // Get the updated user
    const updatedUser = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?'
    ).bind(user.id).first();
    
    return c.json({ success: true, data: updatedUser });
  } catch (error) {
    console.error('Update profile error:', error);
    return c.json({ success: false, error: 'Failed to update profile' }, 500);
  }
});

// Change current user password
usersRouter.put('/me/password', zValidator('json', passwordChangeSchema), async (c) => {
  try {
    const user = c.get('user');
    const { currentPassword, newPassword } = c.req.valid('json');
    
    // Get the current password from the database
    const userWithPassword = await c.env.DB.prepare(
      'SELECT password FROM users WHERE id = ?'
    ).bind(user.id).first<{ password: string }>();
    
    if (!userWithPassword) {
      return c.json({ success: false, error: 'User not found' }, 404);
    }
    
    // Verify the current password
    const isMatch = await comparePassword(currentPassword, userWithPassword.password);
    
    if (!isMatch) {
      return c.json({ success: false, error: 'Current password is incorrect' }, 401);
    }
    
    // Hash the new password
    const hashedPassword = await hashPassword(newPassword);
    
    // Update the password
    await c.env.DB.prepare(
      'UPDATE users SET password = ? WHERE id = ?'
    ).bind(hashedPassword, user.id).run();
    
    return c.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    return c.json({ success: false, error: 'Failed to change password' }, 500);
  }
});

export default usersRouter; 