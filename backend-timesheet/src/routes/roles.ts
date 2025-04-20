import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { authenticate } from '../middleware/auth';
import { requireRole } from '../middleware/auth';

// Define env type for route context
interface RouteEnv {
  DB: D1Database;
}

// Create the roles router
const rolesRouter = new Hono<{ Bindings: RouteEnv }>();

// Apply authentication to all routes
rolesRouter.use('/*', authenticate);

// Schema for role assignment
const roleAssignmentSchema = z.object({
  role: z.enum(['admin', 'manager', 'employee']),
});

// Get all available roles
rolesRouter.get('/', requireRole(['admin']), async (c) => {
  // For MVP, we're using hardcoded roles
  const roles = [
    { id: 'admin', name: 'Administrator', description: 'Full system access' },
    { id: 'manager', name: 'Manager', description: 'Manage employees and approve timesheets' },
    { id: 'employee', name: 'Employee', description: 'Submit timesheets and view own data' }
  ];
  
  return c.json({ success: true, data: roles });
});

// Assign role to user
rolesRouter.post('/admin/users/:id/roles', 
  requireRole(['admin']), 
  zValidator('json', roleAssignmentSchema), 
  async (c) => {
    try {
      const userId = c.req.param('id');
      const { role } = c.req.valid('json');
      const adminUser = c.get('user');
      
      // Check if user exists
      const existingUser = await c.env.DB.prepare(
        'SELECT id, role FROM users WHERE id = ?'
      ).bind(userId).first<{ id: number, role: string }>();
      
      if (!existingUser) {
        return c.json({ success: false, error: 'User not found' }, 404);
      }
      
      // Prevent admin from changing their own role (security measure)
      if (adminUser.id === existingUser.id) {
        return c.json({ success: false, error: 'Cannot change your own role' }, 400);
      }
      
      // Update the user's role
      await c.env.DB.prepare(
        'UPDATE users SET role = ? WHERE id = ?'
      ).bind(role, userId).run();
      
      // Get the updated user
      const updatedUser = await c.env.DB.prepare(
        'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?'
      ).bind(userId).first();
      
      return c.json({ success: true, data: updatedUser });
    } catch (error) {
      console.error('Assign role error:', error);
      return c.json({ success: false, error: 'Failed to assign role' }, 500);
    }
});

// Remove role from user (revert to default 'employee' role)
rolesRouter.delete('/admin/users/:id/roles/:roleId',
  requireRole(['admin']),
  async (c) => {
    try {
      const userId = c.req.param('id');
      const roleId = c.req.param('roleId');
      const adminUser = c.get('user');
      
      // Check if user exists
      const existingUser = await c.env.DB.prepare(
        'SELECT id, role FROM users WHERE id = ?'
      ).bind(userId).first<{ id: number, role: string }>();
      
      if (!existingUser) {
        return c.json({ success: false, error: 'User not found' }, 404);
      }
      
      // Prevent admin from removing their own admin role
      if (adminUser.id === existingUser.id && roleId === 'admin') {
        return c.json({ success: false, error: 'Cannot remove your own admin role' }, 400);
      }
      
      // Check if user has this role
      if (existingUser.role !== roleId) {
        return c.json({ success: false, error: `User does not have role '${roleId}'` }, 400);
      }
      
      // Reset role to 'employee'
      await c.env.DB.prepare(
        'UPDATE users SET role = ? WHERE id = ?'
      ).bind('employee', userId).run();
      
      // Get the updated user
      const updatedUser = await c.env.DB.prepare(
        'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?'
      ).bind(userId).first();
      
      return c.json({ success: true, data: updatedUser });
    } catch (error) {
      console.error('Remove role error:', error);
      return c.json({ success: false, error: 'Failed to remove role' }, 500);
    }
});

export default rolesRouter; 