// lib/inputValidation.js - Input validation utilities for security
const path = require('path');
const fs = require('fs');

/**
 * Validate and sanitize file paths to prevent path traversal
 * @param {string} userPath - User-provided path component
 * @param {string} allowedBase - Base directory that must contain the result
 * @returns {string} Sanitized absolute path
 * @throws {Error} If path traversal is detected
 */
function sanitizeFilePath(userPath, allowedBase) {
  if (!userPath) {
    throw new Error('Path is required');
  }
  
  if (!allowedBase) {
    throw new Error('Base path is required');
  }
  
  // Remove null bytes
  const cleaned = userPath.replace(/\0/g, '');
  
  // Resolve to absolute path
  const resolvedPath = path.resolve(allowedBase, cleaned);
  const resolvedBase = path.resolve(allowedBase);
  
  // Ensure the resolved path is within the allowed base
  if (!resolvedPath.startsWith(resolvedBase + path.sep) && resolvedPath !== resolvedBase) {
    throw new Error(`Path traversal attempt detected: ${userPath}`);
  }
  
  return resolvedPath;
}

/**
 * Validate profile ID format (alphanumeric, dash, underscore only)
 * @param {string} profileId - Profile identifier
 * @returns {string} Validated profile ID
 * @throws {Error} If profile ID is invalid
 */
function validateProfileId(profileId) {
  if (!profileId || typeof profileId !== 'string') {
    throw new Error('Invalid profile ID: must be a non-empty string');
  }
  
  // Only allow safe characters: alphanumeric, dash, underscore
  if (!/^[a-zA-Z0-9_-]+$/.test(profileId)) {
    throw new Error('Profile ID contains invalid characters (only a-z, A-Z, 0-9, -, _ allowed)');
  }
  
  // Prevent path traversal patterns
  if (profileId.includes('..')) {
    throw new Error('Profile ID cannot contain ".." sequences');
  }
  
  // Length limit
  if (profileId.length > 50) {
    throw new Error('Profile ID too long (max 50 characters)');
  }
  
  return profileId;
}

/**
 * Validate project path
 * @param {string} projectPath - Path to project directory
 * @returns {string} Validated absolute path
 * @throws {Error} If path is invalid
 */
function validateProjectPath(projectPath) {
  if (!projectPath || typeof projectPath !== 'string') {
    throw new Error('Invalid project path: must be a non-empty string');
  }
  
  // Check for null bytes
  if (projectPath.includes('\0')) {
    throw new Error('Path contains null bytes');
  }
  
  // Resolve to absolute path
  const resolved = path.resolve(projectPath);
  
  // Basic sanity checks
  if (resolved.length > 500) {
    throw new Error('Path too long (max 500 characters)');
  }
  
  // Check if path exists (optional - comment out if not needed)
  try {
    fs.accessSync(resolved);
  } catch (error) {
    throw new Error(`Path does not exist or is not accessible: ${resolved}`);
  }
  
  return resolved;
}

/**
 * Validate filename (basename only, no path components)
 * @param {string} filename - Filename to validate
 * @returns {string} Validated filename (basename only)
 * @throws {Error} If filename is invalid
 */
function validateFilename(filename) {
  if (!filename || typeof filename !== 'string') {
    throw new Error('Invalid filename: must be a non-empty string');
  }
  
  // Extract basename to remove any path components
  const basename = path.basename(filename);
  
  // Check for dangerous patterns
  if (basename.includes('..') || basename === '.' || basename === '') {
    throw new Error('Invalid filename: contains dangerous patterns');
  }
  
  // Check for null bytes
  if (basename.includes('\0')) {
    throw new Error('Filename contains null bytes');
  }
  
  // Length limit
  if (basename.length > 255) {
    throw new Error('Filename too long (max 255 characters)');
  }
  
  return basename;
}

/**
 * Sanitize command arguments to prevent command injection
 * @param {string} arg - Command argument
 * @returns {string} Sanitized argument
 * @throws {Error} If argument contains dangerous characters
 */
function sanitizeCommandArg(arg) {
  if (!arg || typeof arg !== 'string') {
    throw new Error('Invalid command argument');
  }
  
  // Check for command injection patterns
  const dangerousPatterns = [
    ';', '|', '&', '$', '`', '\n', '\r',
    '$(', '${', '<!--', '-->'
  ];
  
  for (const pattern of dangerousPatterns) {
    if (arg.includes(pattern)) {
      throw new Error(`Command argument contains dangerous pattern: ${pattern}`);
    }
  }
  
  return arg;
}

module.exports = {
  sanitizeFilePath,
  validateProfileId,
  validateProjectPath,
  validateFilename,
  sanitizeCommandArg
};
