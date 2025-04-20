import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authenticate } from '../middleware/auth';
import { requireRole } from '../middleware/auth';
import { hashPassword } from '../utils/auth';

// Define env type for route context
interface RouteEnv {
  DB: D1Database;
}

// Create the admin router
const adminRouter = new Hono<{ Bindings: RouteEnv }>();

// Apply authentication and admin role requirement to all routes
adminRouter.use('/*', authenticate, requireRole(['admin']));

// Schema for user update by admin
const userUpdateSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').optional(),
  email: z.string().email('Invalid email address').optional(),
  role: z.enum(['admin', 'manager', 'employee']).optional(),
  password: z.string().min(8, 'Password must be at least 8 characters').optional()
});

// Get all users (admin only)
adminRouter.get('/users', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at, updated_at FROM users ORDER BY created_at DESC'
    ).all();
    
    return c.json({ success: true, data: results });
  } catch (error) {
    console.error('Get all users error:', error);
    return c.json({ success: false, error: 'Failed to get users' }, 500);
  }
});

// Update user by ID (admin only)
adminRouter.put('/users/:id', zValidator('json', userUpdateSchema), async (c) => {
  try {
    const userId = c.req.param('id');
    const updates = c.req.valid('json');
    
    // Check if user exists
    const existingUser = await c.env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(userId).first();
    
    if (!existingUser) {
      return c.json({ success: false, error: 'User not found' }, 404);
    }
    
    // Handle password update separately if provided
    let hashedPasswordUpdate = null;
    if (updates.password) {
      hashedPasswordUpdate = await hashPassword(updates.password);
      // Remove the plain text password from updates
      delete updates.password;
    }
    
    // Generate dynamic update query based on provided fields
    let fields = Object.keys(updates).filter(key => 
      updates[key as keyof typeof updates] !== undefined
    );
    
    // If email is being updated, check it's not already taken
    if (updates.email) {
      const emailCheck = await c.env.DB.prepare(
        'SELECT id FROM users WHERE email = ? AND id != ?'
      ).bind(updates.email, userId).first();
      
      if (emailCheck) {
        return c.json({ success: false, error: 'Email already in use' }, 409);
      }
    }
    
    // Handle the case where we only update the password
    if (hashedPasswordUpdate && fields.length === 0) {
      await c.env.DB.prepare(
        'UPDATE users SET password = ? WHERE id = ?'
      ).bind(hashedPasswordUpdate, userId).run();
    } 
    // Handle updates to other fields (and possibly password)
    else if (fields.length > 0) {
      let setClause = fields.map(field => `${field} = ?`).join(', ');
      let values = fields.map(field => updates[field as keyof typeof updates]);
      
      // Add password update if present
      if (hashedPasswordUpdate) {
        setClause += ', password = ?';
        values.push(hashedPasswordUpdate);
      }
      
      await c.env.DB.prepare(
        `UPDATE users SET ${setClause} WHERE id = ?`
      ).bind(...values, userId).run();
    } else {
      return c.json({ success: false, error: 'No fields to update' }, 400);
    }
    
    // Get the updated user
    const updatedUser = await c.env.DB.prepare(
      'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?'
    ).bind(userId).first();
    
    return c.json({ success: true, data: updatedUser });
  } catch (error) {
    console.error('Update user error:', error);
    return c.json({ success: false, error: 'Failed to update user' }, 500);
  }
});

// Delete user by ID (admin only)
adminRouter.delete('/users/:id', async (c) => {
  try {
    const userId = c.req.param('id');
    const adminUser = c.get('user');
    
    // Prevent admin from deleting themselves
    if (adminUser.id === parseInt(userId)) {
      return c.json({ success: false, error: 'Cannot delete your own account' }, 400);
    }
    
    // Check if user exists
    const existingUser = await c.env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(userId).first();
    
    if (!existingUser) {
      return c.json({ success: false, error: 'User not found' }, 404);
    }
    
    // Delete the user
    await c.env.DB.prepare(
      'DELETE FROM users WHERE id = ?'
    ).bind(userId).run();
    
    return c.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    return c.json({ success: false, error: 'Failed to delete user' }, 500);
  }
});

export default adminRouter; 