import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration - restrict to specific origins in production
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']
    : true, // Allow all origins in development
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Limit request body size to prevent DoS attacks
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

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

app.post('/api/conversions/log', async (req, res) => {
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

app.post('/api/clicks/log', async (req, res) => {
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

app.post('/api/report/build', async (req, res) => {
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

