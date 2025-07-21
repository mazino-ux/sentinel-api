const ROLES = {
    USER: 'user',
    ADMIN: 'admin',
    SUPER_ADMIN: 'super_admin',
  };  // Role-based access control
  
  // Token & security settings
  const TOKEN_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes for verification code
  const SALT_ROUNDS = {
    production: 12,
    development: 8
  };
  
module.exports = { ROLES, TOKEN_EXPIRY_MS, SALT_ROUNDS }; // Exporting constants for use in other parts of the application
