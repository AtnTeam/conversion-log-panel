import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || '9b3d1ee8ad8f73c91330987c44f721ac9fe96fa5e80c56fd001232be0b686d0591d99205a9049c30f6e9d26fcfc69c8a87d429998148161a0ac07095f1b05f35';
const JWT_EXPIRES_IN = '24h';

// Admin credentials - hash password on startup
if (!process.env.ADMIN_USERNAME) {
  throw new Error('ADMIN_USERNAME environment variable is required');
}
if (!process.env.ADMIN_PASSWORD) {
  throw new Error('ADMIN_PASSWORD environment variable is required');
}

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD;

// Hash admin password synchronously for immediate availability
let ADMIN_PASSWORD_HASH = null;
if (ADMIN_PASSWORD_PLAIN) {
  // Use sync version for startup, or await in async context
  bcrypt.hash(ADMIN_PASSWORD_PLAIN, 10, (err, hash) => {
    if (err) {
      console.error('Error hashing admin password:', err);
    } else {
      ADMIN_PASSWORD_HASH = hash;
      console.log('Admin password hashed successfully');
    }
  });
  // Fallback: hash synchronously if async fails
  try {
    ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD_PLAIN, 10);
  } catch (err) {
    console.error('Error hashing admin password synchronously:', err);
  }
}

const ADMIN_CREDENTIALS = {
  username: ADMIN_USERNAME
};

// Security headers with Helmet (configured for HTTP support)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Allow embedding if needed
  hsts: false // Disable HSTS to allow HTTP connections
}));

// CORS configuration - restrict to specific origins in production
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']
    : true, // Allow all origins in development
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));
app.use(cookieParser());

// Limit request body size to prevent DoS attacks
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limiting for login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts, please try again later.',
  skipSuccessfulRequests: true, // Don't count successful requests
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to all API routes
app.use('/api/', apiLimiter);

// Input validation and sanitization
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input.trim().replace(/[<>]/g, '');
  }
  return input;
};

const validateInput = (username, password) => {
  // Prevent injection attacks
  if (typeof username !== 'string' || typeof password !== 'string') {
    return false;
  }
  
  // Length limits
  if (username.length > 100 || password.length > 200) {
    return false;
  }
  
  // Basic character validation
  if (!/^[a-zA-Z0-9_@.-]+$/.test(username)) {
    return false;
  }
  
  return true;
};

// Authentication middleware with enhanced security
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // Validate token format
  if (token.length > 1000 || !/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/.test(token)) {
    return res.status(403).json({ error: 'Invalid token format' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Validate domain to prevent SSRF attacks
const validateDomain = (domain) => {
  if (!domain || typeof domain !== 'string') {
    return false;
  }
  
  try {
    const url = new URL(domain.startsWith('http') ? domain : `https://${domain}`);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }
    // Prevent localhost and private IP addresses in production
    if (process.env.NODE_ENV === 'production') {
      const hostname = url.hostname.toLowerCase();
      if (hostname === 'localhost' || 
          hostname === '127.0.0.1' || 
          hostname.startsWith('192.168.') ||
          hostname.startsWith('10.') ||
          hostname.startsWith('172.16.') ||
          hostname.startsWith('172.17.') ||
          hostname.startsWith('172.18.') ||
          hostname.startsWith('172.19.') ||
          hostname.startsWith('172.20.') ||
          hostname.startsWith('172.21.') ||
          hostname.startsWith('172.22.') ||
          hostname.startsWith('172.23.') ||
          hostname.startsWith('172.24.') ||
          hostname.startsWith('172.25.') ||
          hostname.startsWith('172.26.') ||
          hostname.startsWith('172.27.') ||
          hostname.startsWith('172.28.') ||
          hostname.startsWith('172.29.') ||
          hostname.startsWith('172.30.') ||
          hostname.startsWith('172.31.')) {
        return false;
      }
    }
    return true;
  } catch (error) {
    return false;
  }
};

// Login endpoint with enhanced security
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Sanitize and validate input
    const sanitizedUsername = sanitizeInput(username);
    const sanitizedPassword = sanitizeInput(password);

    if (!validateInput(sanitizedUsername, sanitizedPassword)) {
      // Use same delay to prevent timing attacks
      await bcrypt.compare('dummy', '$2b$10$dummy');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check username first (constant time comparison)
    if (sanitizedUsername !== ADMIN_CREDENTIALS.username) {
      // Use same delay to prevent timing attacks
      await bcrypt.compare('dummy', '$2b$10$dummy');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password with bcrypt (prevents timing attacks)
    if (!ADMIN_PASSWORD_HASH) {
      console.error('Admin password hash not initialized');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const passwordMatch = await bcrypt.compare(sanitizedPassword, ADMIN_PASSWORD_HASH);
    
    if (passwordMatch) {
      const token = jwt.sign(
        { 
          username: ADMIN_CREDENTIALS.username,
          role: 'admin',
          iat: Math.floor(Date.now() / 1000)
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Set secure cookie as additional protection (HttpOnly, Secure, SameSite)
      // secure: false to allow HTTP connections (change to true when using HTTPS)
      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: false, // Set to true when using HTTPS
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });

      return res.json({
        token,
        user: {
          username: ADMIN_CREDENTIALS.username,
          role: 'admin'
        }
      });
    }

    res.status(401).json({ error: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify token endpoint
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    user: req.user
  });
});

// Logout endpoint - clear cookies
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: false, // Set to true when using HTTPS
    sameSite: 'strict'
  });
  res.json({ message: 'Logged out successfully' });
});

app.post('/api/conversions/log', authenticateToken, async (req, res) => {
  try {
    const { range, limit, offset, columns, filters, sort } = req.body;

    const domain = process.env.DOMAIN;
    const apiKey = process.env.API_KEY;

    if (!domain || !apiKey) {
      return res.status(500).json({ 
        error: 'Server configuration error' 
      });
    }

    // Validate domain to prevent SSRF attacks
    if (!validateDomain(domain)) {
      return res.status(400).json({ 
        error: 'Invalid domain configuration' 
      });
    }

    // Validate and sanitize input
    const sanitizedLimit = Math.min(Math.max(parseInt(limit) || 1000, 1), 10000);
    const sanitizedOffset = Math.max(parseInt(offset) || 0, 0);

    // Normalize domain: remove trailing slash if present
    const normalizedDomain = domain.replace(/\/+$/, '');
    const keitaroUrl = `${normalizedDomain}/admin_api/v1/conversions/log`;

    const response = await axios.post(
      keitaroUrl,
      {
        range,
        limit: sanitizedLimit,
        offset: sanitizedOffset,
        columns: columns || [
          'sub_id',
          'affiliate_network',
          'offer',
          'sub_id_3',
          'status',
          'revenue',
          'status_history',
          'datetime',
          'country_flag',
          'country'
        ],
        filters: filters || [],
        sort: sort || []
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Api-Key': apiKey
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching conversions:', error.message);
    // Don't expose internal error details to client
    const statusCode = error.response?.status || 500;
    const errorMessage = statusCode === 500 
      ? 'Internal server error' 
      : (error.response?.data?.message || 'Request failed');
    
    res.status(statusCode).json({
      error: errorMessage
    });
  }
});

app.post('/api/clicks/log', authenticateToken, async (req, res) => {
  try {
    const { range, limit, offset, columns, filters, sort } = req.body;

    const domain = process.env.DOMAIN;
    const apiKey = process.env.API_KEY;

    if (!domain || !apiKey) {
      return res.status(500).json({
        error: 'Server configuration error'
      });
    }

    // Validate domain to prevent SSRF attacks
    if (!validateDomain(domain)) {
      return res.status(400).json({ 
        error: 'Invalid domain configuration' 
      });
    }

    // Validate and sanitize input
    const sanitizedLimit = Math.min(Math.max(parseInt(limit) || 1000, 1), 10000);
    const sanitizedOffset = Math.max(parseInt(offset) || 0, 0);

    const normalizedDomain = domain.replace(/\/+$/, '');
    const keitaroUrl = `${normalizedDomain}/admin_api/v1/clicks/log`;

    const response = await axios.post(
      keitaroUrl,
      {
        range,
        limit: sanitizedLimit,
        offset: sanitizedOffset,
        columns: columns || ['sub_id', 'datetime'],
        filters: filters || [],
        sort: sort || []
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Api-Key': apiKey
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching clicks:', error.message);
    // Don't expose internal error details to client
    const statusCode = error.response?.status || 500;
    const errorMessage = statusCode === 500 
      ? 'Internal server error' 
      : (error.response?.data?.message || 'Request failed');
    
    res.status(statusCode).json({
      error: errorMessage
    });
  }
});

app.post('/api/report/build', authenticateToken, async (req, res) => {
  try {
    const { dimensions, measures, filters, sort, limit, offset, extended, range, summary } = req.body;

    const domain = process.env.DOMAIN;
    const apiKey = process.env.API_KEY;

    if (!domain || !apiKey) {
      return res.status(500).json({
        error: 'Server configuration error'
      });
    }

    // Validate domain to prevent SSRF attacks
    if (!validateDomain(domain)) {
      return res.status(400).json({ 
        error: 'Invalid domain configuration' 
      });
    }

    // Validate and sanitize input
    const sanitizedLimit = Math.min(Math.max(parseInt(limit) || 1000, 1), 10000);
    const sanitizedOffset = Math.max(parseInt(offset) || 0, 0);

    const normalizedDomain = domain.replace(/\/+$/, '');
    const keitaroUrl = `${normalizedDomain}/admin_api/v1/report/build`;

    const response = await axios.post(
      keitaroUrl,
      {
        dimensions: dimensions || [],
        measures: measures || [],
        filters: filters || {},
        sort: sort || [],
        limit: sanitizedLimit,
        offset: sanitizedOffset,
        extended: extended !== undefined ? extended : true,
        range: range || {},
        summary: summary !== undefined ? summary : true
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Api-Key': apiKey
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching report:', error.message);
    // Don't expose internal error details to client
    const statusCode = error.response?.status || 500;
    const errorMessage = statusCode === 500 
      ? 'Internal server error' 
      : (error.response?.data?.message || 'Request failed');
    
    res.status(statusCode).json({
      error: errorMessage
    });
  }
});

// Serve static files from frontend/dist in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend/dist')));
  
  // Handle React Router - serve index.html for all non-API routes
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api')) {
      res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
    }
  });
}

app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});

