import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// JWT Secret key - should be stored in environment variables in production
const JWT_SECRET = 'your-secret-key-change-in-production';
const JWT_EXPIRY = '24h'; // Token expires in 24 hours

// User interface for JWT payloads
export interface JwtUser {
  id: number;
  email: string;
  role: string;
}

/**
 * Hash a password using bcrypt
 */
export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

/**
 * Compare a password with a hashed password
 */
export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};

/**
 * Generate a JWT token for a user
 */
export const generateToken = (user: JwtUser): string => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
};

/**
 * Verify a JWT token
 */
export const verifyToken = (token: string): JwtUser | null => {
  try {
    return jwt.verify(token, JWT_SECRET) as JwtUser;
  } catch (error) {
    return null;
  }
};

/**
 * Generate a random token for password reset
 */
export const generateResetToken = (): string => {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
};

/**
 * Check if a role has access to a resource
 */
export const hasRole = (userRole: string, requiredRoles: string[]): boolean => {
  return requiredRoles.includes(userRole);
}; 