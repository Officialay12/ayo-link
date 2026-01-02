const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// CORS - Allow all origins in development, restrict in production
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, etc)
        if (!origin) return callback(null, true);

        // Allow localhost for development
        if (origin.includes('localhost')) {
            return callback(null, true);
        }

        // Allow your deployed domains
        const allowedOrigins = [
            'https://ayo-link.onrender.com',
            'https://www.ayo.link',
            'https://ayo.link'
        ];

        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});

app.use('/api/', apiLimiter);

// Database configuration
const DB_FILE = process.env.NODE_ENV === 'production'
    ? path.join(__dirname, 'data', 'urls.json')
    : path.join(__dirname, 'urls.json');

const DATA_DIR = path.dirname(DB_FILE);

// Ensure data directory exists
async function ensureDataDir() {
    try {
        await fs.access(DATA_DIR);
    } catch {
        await fs.mkdir(DATA_DIR, { recursive: true });
    }
}


// Generate custom API key starting with "ayo_"
function generateApiKey() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(12).toString('hex');
    return `ayo_${timestamp}_${random}`.toLowerCase();
}

// Generate short ID
function generateShortId() {
    return crypto.randomBytes(4).toString('hex');
}

// Validate URL
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return ['http:', 'https:'].includes(url.protocol);
    } catch (_) {
        return false;
    }
}

// Validate slug (custom short code)
function isValidSlug(slug) {
    return /^[a-zA-Z0-9_-]+$/.test(slug) && slug.length <= 50;
}

// Database operations
async function initDatabase() {
    await ensureDataDir();

    try {
        await fs.access(DB_FILE);
        console.log('Database file exists');
    } catch (error) {
        console.log('Creating new database file...');
        const initialData = {
            urls: [],
            stats: {
                totalUrls: 0,
                totalClicks: 0,
                createdAt: new Date().toISOString(),
                lastUpdated: new Date().toISOString()
            },
            apiKeys: {},
            settings: {
                maxUrlsPerUser: 1000,
                maxCustomSlugLength: 50,
                defaultShortIdLength: 8,
                version: '1.0.0'
            }
        };
        await writeDatabase(initialData);
        console.log('Database initialized successfully');
    }
}

async function readDatabase() {
    try {
        const data = await fs.readFile(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading database:', error);
        // Return empty database if file doesn't exist
        return {
            urls: [],
            stats: { totalUrls: 0, totalClicks: 0, createdAt: new Date().toISOString() },
            apiKeys: {},
            settings: {
                maxUrlsPerUser: 1000,
                maxCustomSlugLength: 50,
                defaultShortIdLength: 8,
                version: '1.0.0'
            }
        };
    }
}

async function writeDatabase(data) {
    try {
        data.stats.lastUpdated = new Date().toISOString();
        await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error writing to database:', error);
        throw error;
    }
}

// API Routes

// 1. Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'Ayo.link URL Shortener',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 2. Create short URL
app.post('/api/shorten', async (req, res) => {
    try {
        const { url, customSlug, apiKey } = req.body;

        // Validate URL
        if (!url || !isValidUrl(url)) {
            return res.status(400).json({
                error: 'Invalid URL provided. URL must start with http:// or https://'
            });
        }

        // Validate custom slug if provided
        if (customSlug && !isValidSlug(customSlug)) {
            return res.status(400).json({
                error: 'Invalid custom slug. Use only letters, numbers, hyphens, and underscores (max 50 chars).'
            });
        }

        const db = await readDatabase();

        // Check if custom slug already exists
        let shortId;
        if (customSlug) {
            const existing = db.urls.find(u => u.shortId === customSlug);
            if (existing) {
                return res.status(409).json({
                    error: 'Custom slug already in use. Please choose a different one.'
                });
            }
            shortId = customSlug;
        } else {
            // Generate unique short ID
            do {
                shortId = generateShortId();
            } while (db.urls.find(u => u.shortId === shortId));
        }

        // Check user limits if API key provided
        if (apiKey && db.apiKeys[apiKey]) {
            const userUrls = db.urls.filter(u => u.createdBy === apiKey);
            const maxUrls = db.settings?.maxUrlsPerUser || 1000;
            if (userUrls.length >= maxUrls) {
                return res.status(429).json({
                    error: `You have reached the maximum limit of ${maxUrls} URLs.`
                });
            }
        }

        // Create URL entry
        const urlEntry = {
            id: Date.now().toString(),
            shortId,
            originalUrl: url,
            createdAt: new Date().toISOString(),
            clicks: 0,
            lastAccessed: null,
            createdBy: apiKey || 'web',
            ipAddress: req.ip,
            userAgent: req.get('user-agent') || 'unknown'
        };

        // Save to database
        db.urls.push(urlEntry);
        db.stats.totalUrls++;

        // Track API key usage
        if (apiKey) {
            if (!db.apiKeys[apiKey]) {
                db.apiKeys[apiKey] = {
                    name: 'Anonymous User',
                    email: 'unknown@example.com',
                    createdAt: new Date().toISOString(),
                    urlsCreated: 0,
                    lastUsed: new Date().toISOString()
                };
            }
            db.apiKeys[apiKey].urlsCreated++;
            db.apiKeys[apiKey].lastUsed = new Date().toISOString();
        }

        await writeDatabase(db);

        // Get domain for short URL
        const domain = process.env.DOMAIN || `${req.protocol}://${req.get('host')}`;

        // Return success response
        res.json({
            success: true,
            shortId,
            shortUrl: `${domain}/${shortId}`,
            originalUrl: url,
            createdAt: urlEntry.createdAt,
            message: 'URL shortened successfully!',
            brand: 'Ayo.link'
        });

    } catch (error) {
        console.error('Error shortening URL:', error);
        res.status(500).json({
            error: 'Internal server error. Please try again later.'
        });
    }
});

// 3. Redirect short URL
app.get('/:shortId', async (req, res) => {
    try {
        const { shortId } = req.params;
        const db = await readDatabase();

        const urlEntry = db.urls.find(u => u.shortId === shortId);

        if (!urlEntry) {
            return res.status(404).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Ayo.link - URL Not Found</title>
                    <style>
                        body {
                            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                            text-align: center;
                            padding: 50px;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }
                        .container {
                            background: rgba(255, 255, 255, 0.1);
                            backdrop-filter: blur(10px);
                            padding: 50px;
                            border-radius: 20px;
                            max-width: 600px;
                        }
                        h1 {
                            color: white;
                            font-size: 48px;
                            margin-bottom: 20px;
                        }
                        p {
                            font-size: 18px;
                            margin-bottom: 30px;
                            opacity: 0.9;
                        }
                        a {
                            display: inline-block;
                            background: white;
                            color: #667eea;
                            padding: 15px 30px;
                            border-radius: 10px;
                            text-decoration: none;
                            font-weight: 600;
                            transition: transform 0.3s;
                        }
                        a:hover {
                            transform: translateY(-2px);
                        }
                        .logo {
                            font-size: 24px;
                            font-weight: 800;
                            margin-bottom: 30px;
                            color: white;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="logo">Ayo.link</div>
                        <h1>404 - URL Not Found</h1>
                        <p>The requested short URL does not exist or has been deleted.</p>
                        <a href="/">Go to Ayo.link Homepage</a>
                    </div>
                </body>
                </html>
            `);
        }

        // Update stats
        urlEntry.clicks++;
        urlEntry.lastAccessed = new Date().toISOString();
        db.stats.totalClicks++;

        await writeDatabase(db);

        // Redirect to original URL
        res.redirect(301, urlEntry.originalUrl);

    } catch (error) {
        console.error('Error redirecting:', error);
        res.status(500).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Ayo.link - Server Error</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    h1 { color: #e53e3e; }
                </style>
            </head>
            <body>
                <h1>500 - Server Error</h1>
                <p>Something went wrong. Please try again later.</p>
                <a href="/">Go to Homepage</a>
            </body>
            </html>
        `);
    }
});

// 4. Get all URLs (requires API key)
app.get('/api/urls', async (req, res) => {
    try {
        const apiKey = req.query.apiKey || req.headers['x-api-key'];

        if (!apiKey) {
            return res.status(401).json({
                error: 'API key required. Get one from /api/generate-key'
            });
        }

        const db = await readDatabase();

        if (!db.apiKeys[apiKey]) {
            return res.status(403).json({
                error: 'Invalid API key'
            });
        }

        // Return URLs created by this API key
        const userUrls = db.urls.filter(u => u.createdBy === apiKey);

        // Get domain for short URLs
        const domain = process.env.DOMAIN || `${req.protocol}://${req.get('host')}`;

        res.json({
            success: true,
            count: userUrls.length,
            urls: userUrls.map(url => ({
                id: url.id,
                shortId: url.shortId,
                shortUrl: `${domain}/${url.shortId}`,
                originalUrl: url.originalUrl,
                clicks: url.clicks,
                createdAt: url.createdAt,
                lastAccessed: url.lastAccessed
            })),
            brand: 'Ayo.link'
        });

    } catch (error) {
        console.error('Error fetching URLs:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

// 5. Get statistics
app.get('/api/stats', async (req, res) => {
    try {
        const db = await readDatabase();

        // Calculate daily stats (last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const recentUrls = db.urls.filter(url =>
            new Date(url.createdAt) > thirtyDaysAgo
        );

        const recentClicks = db.urls.reduce((sum, url) =>
            new Date(url.lastAccessed) > thirtyDaysAgo ? sum + url.clicks : sum, 0
        );

        // Get domain for short URLs
        const domain = process.env.DOMAIN || `${req.protocol}://${req.get('host')}`;

        res.json({
            success: true,
            brand: 'Ayo.link',
            stats: db.stats,
            recentStats: {
                last30Days: {
                    urlsCreated: recentUrls.length,
                    clicks: recentClicks
                }
            },
            activeUsers: Object.keys(db.apiKeys).length,
            topUrls: db.urls
                .sort((a, b) => b.clicks - a.clicks)
                .slice(0, 10)
                .map(u => ({
                    shortId: u.shortId,
                    shortUrl: `${domain}/${u.shortId}`,
                    clicks: u.clicks,
                    originalUrl: u.originalUrl.substring(0, 50) + '...',
                    createdAt: u.createdAt
                })),
            settings: db.settings,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

// 6. Generate API key (starts with "ayo_")
app.post('/api/generate-key', async (req, res) => {
    try {
        const { name, email } = req.body;

        if (!name || !email) {
            return res.status(400).json({
                error: 'Name and email are required'
            });
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Please provide a valid email address'
            });
        }

        const apiKey = generateApiKey();
        const db = await readDatabase();

        // Check if email already has a key
        const existingKey = Object.keys(db.apiKeys).find(key =>
            db.apiKeys[key].email === email
        );

        if (existingKey) {
            return res.status(409).json({
                error: 'An API key already exists for this email address',
                existingKey
            });
        }

        db.apiKeys[apiKey] = {
            name,
            email,
            createdAt: new Date().toISOString(),
            urlsCreated: 0,
            lastUsed: new Date().toISOString()
        };

        await writeDatabase(db);

        res.json({
            success: true,
            apiKey,
            message: 'Save this API key securely. It will not be shown again.',
            warning: 'Do not share your API key publicly. Store it in environment variables.',
            brand: 'Ayo.link',
            createdAt: new Date().toISOString(),
            limits: {
                maxUrlsPerUser: db.settings?.maxUrlsPerUser || 1000,
                rateLimit: '100 requests per 15 minutes'
            }
        });

    } catch (error) {
        console.error('Error generating API key:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

// 7. Delete URL
app.delete('/api/url/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const apiKey = req.query.apiKey || req.headers['x-api-key'];

        if (!apiKey) {
            return res.status(401).json({
                error: 'API key required'
            });
        }

        const db = await readDatabase();

        if (!db.apiKeys[apiKey]) {
            return res.status(403).json({
                error: 'Invalid API key'
            });
        }

        const urlIndex = db.urls.findIndex(u => u.id === id && u.createdBy === apiKey);

        if (urlIndex === -1) {
            return res.status(404).json({
                error: 'URL not found or access denied'
            });
        }

        // Remove URL
        const [removedUrl] = db.urls.splice(urlIndex, 1);
        db.stats.totalUrls--;

        await writeDatabase(db);

        res.json({
            success: true,
            message: 'URL deleted successfully',
            deletedUrl: removedUrl.shortId
        });

    } catch (error) {
        console.error('Error deleting URL:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

// 8. Get API key info
app.get('/api/key-info', async (req, res) => {
    try {
        const apiKey = req.query.apiKey || req.headers['x-api-key'];

        if (!apiKey) {
            return res.status(401).json({
                error: 'API key required'
            });
        }

        const db = await readDatabase();

        if (!db.apiKeys[apiKey]) {
            return res.status(403).json({
                error: 'Invalid API key'
            });
        }

        const keyInfo = db.apiKeys[apiKey];
        const userUrls = db.urls.filter(u => u.createdBy === apiKey);

        res.json({
            success: true,
            keyInfo: {
                name: keyInfo.name,
                email: keyInfo.email,
                createdAt: keyInfo.createdAt,
                lastUsed: keyInfo.lastUsed,
                urlsCreated: keyInfo.urlsCreated
            },
            usage: {
                totalUrls: userUrls.length,
                totalClicks: userUrls.reduce((sum, url) => sum + url.clicks, 0),
                urls: userUrls.map(url => ({
                    shortId: url.shortId,
                    clicks: url.clicks,
                    createdAt: url.createdAt
                }))
            },
            brand: 'Ayo.link'
        });

    } catch (error) {
        console.error('Error fetching key info:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

// 9. Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Global error:', err);
    res.status(500).json({
        error: 'Something went wrong!',
        message: process.env.NODE_ENV === 'production' ? null : err.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        availableEndpoints: [
            'POST /api/shorten',
            'GET /api/urls',
            'GET /api/stats',
            'POST /api/generate-key',
            'DELETE /api/url/:id',
            'GET /api/key-info',
            'GET /api/health'
        ],
        brand: 'Ayo.link'
    });
});

// Start server
async function startServer() {
    try {
        await initDatabase();

        const PORT = process.env.PORT || 3000;
        const HOST = process.env.HOST || '0.0.0.0';

        app.listen(PORT, HOST, () => {
            console.log(`
            ╔═══════════════════════════════════════════════════════╗
            ║                                                       ║
            ║   🚀 Ayo.link URL Shortener - Production Ready!       ║
            ║                                                       ║
            ╠═══════════════════════════════════════════════════════╣
            ║                                                       ║
            ║   🌐 Frontend: http://${HOST}:${PORT}                 ║
            ║   🔗 API Base: http://${HOST}:${PORT}/api             ║
            ║   📁 Database: ${DB_FILE}                             ║
            ║   🛡️  Environment: ${process.env.NODE_ENV || 'development'} ║
            ║                                                       ║
            ╠═══════════════════════════════════════════════════════╣
            ║                                                       ║
            ║   📋 Available Endpoints:                             ║
            ║   POST   /api/shorten     - Create short URL          ║
            ║   GET    /api/urls        - Get your URLs             ║
            ║   GET    /api/stats       - Get statistics            ║
            ║   POST   /api/generate-key - Generate API key         ║
            ║   DELETE /api/url/:id     - Delete URL                ║
            ║   GET    /api/key-info    - Get API key info          ║
            ║   GET    /api/health      - Health check              ║
            ║   GET    /:shortId        - Redirect to URL           ║
            ║                                                       ║
            ╚═══════════════════════════════════════════════════════╝
            `);
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
