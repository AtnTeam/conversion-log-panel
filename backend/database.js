import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize database
const dbPath = path.join(__dirname, 'users.db');
const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create users table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    campaign_group_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// User operations
export const getUserByLogin = (login) => {
  const stmt = db.prepare('SELECT * FROM users WHERE login = ?');
  return stmt.get(login);
};

export const getAllUsers = () => {
  const stmt = db.prepare('SELECT id, login, campaign_group_id, created_at FROM users ORDER BY created_at DESC');
  return stmt.all();
};

export const createUser = async (login, password, campaignGroupId) => {
  // Validate input
  if (!login || !password || !campaignGroupId) {
    throw new Error('Login, password and campaign group ID are required');
  }

  // Check if user already exists
  const existingUser = getUserByLogin(login);
  if (existingUser) {
    throw new Error('User with this login already exists');
  }

  // Hash password
  const passwordHash = await bcrypt.hash(password, 10);

  // Insert user
  const stmt = db.prepare('INSERT INTO users (login, password_hash, campaign_group_id) VALUES (?, ?, ?)');
  const result = stmt.run(login, passwordHash, campaignGroupId);
  
  return {
    id: result.lastInsertRowid,
    login,
    campaign_group_id: campaignGroupId
  };
};

export const deleteUser = (id) => {
  const stmt = db.prepare('DELETE FROM users WHERE id = ?');
  const result = stmt.run(id);
  return result.changes > 0;
};

export const verifyUserPassword = async (login, password) => {
  const user = getUserByLogin(login);
  if (!user) {
    return null;
  }

  const isValid = await bcrypt.compare(password, user.password_hash);
  if (!isValid) {
    return null;
  }

  return {
    id: user.id,
    login: user.login,
    campaign_group_id: user.campaign_group_id
  };
};

export default db;

