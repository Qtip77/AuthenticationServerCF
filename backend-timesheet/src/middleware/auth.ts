import { Context, Next } from 'hono';
import { verifyToken, hasRole } from '../utils/auth';

// Define a type for user in request context
declare module 'hono' {
  interface ContextVariableMap {
    user: {
      id: number;
      email: string;
      role: string;
    };
  }
}

/**
 * Middleware to authenticate a user from JWT token in Authorization header
 */
export const authenticate = async (c: Context, next: Next) => {
  try {
    // Get the token from the Authorization header
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ success: false, error: 'Unauthorized - No token provided' }, 401);
    }
    
    // Extract the token
    const token = authHeader.split(' ')[1];
    
    // Verify the token
    const user = verifyToken(token);
    
    if (!user) {
      return c.json({ success: false, error: 'Unauthorized - Invalid token' }, 401);
    }
    
    // Set the user in the context for use in route handlers
    c.set('user', {
      id: user.id,
      email: user.email,
      role: user.role
    });
    
    // Continue to the route handler
    await next();
  } catch (error) {
    console.error('Authentication error:', error);
    return c.json({ success: false, error: 'Unauthorized - Authentication error' }, 401);
  }
};

/**
 * Middleware to check if user has required role
 */
export const requireRole = (roles: string[]) => {
  return async (c: Context, next: Next) => {
    try {
      // First ensure the user is authenticated
      const user = c.get('user');
      
      if (!user) {
        return c.json({ success: false, error: 'Unauthorized - Authentication required' }, 401);
      }
      
      // Check if the user has one of the required roles
      if (!hasRole(user.role, roles)) {
        return c.json({ 
          success: false, 
          error: `Forbidden - Requires one of these roles: ${roles.join(', ')}` 
        }, 403);
      }
      
      // User has the required role, continue
      await next();
    } catch (error) {
      console.error('Role verification error:', error);
      return c.json({ success: false, error: 'Unauthorized - Role verification error' }, 401);
    }
  };
}; 