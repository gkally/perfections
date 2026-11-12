// ============================================================
//  server.js — Vertex Talent Recruitment Platform
//  Database: JSONBin.io | Jobs API: Remotive (free, no key)
//  Node.js + Express + Multer + JSONBin
//  Run: npm install express cors multer axios dotenv
//       node server.js
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
//  CONFIGURATION
// ============================================================
const JSONBIN_API_KEY = process.env.JSONBIN_API_KEY || '$2a$10$rCMZ5BGigbU.r61CyfSSMuDVGGKbVun2m0Q/crGUa4hM8vmfP81g2';
const JSONBIN_BIN_ID  = process.env.JSONBIN_BIN_ID  || '6af59487ffd5d16053bbab85';
const JSONBIN_BASE    = 'https://api.jsonbin.io/v3';

// Admin credentials (change in production via env)
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'vertex2026!';

// ============================================================
//  MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads folder
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// Multer storage for profile pictures
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname) || '.jpg';
        cb(null, 'avatar_' + Date.now() + '_' + Math.round(Math.random() * 1e6) + ext);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (/^image\/(jpeg|jpg|png)$/.test(file.mimetype)) cb(null, true);
        else cb(new Error('Only JPG/PNG images allowed'));
    }
});

// ============================================================
//  JSONBIN HELPERS
// ============================================================
const jsonbinHeaders = {
    'Content-Type': 'application/json',
    'X-Master-Key': JSONBIN_API_KEY,
    'X-Bin-Meta': 'false'
};

// In-memory cache to reduce JSONBin calls (free tier: limited)
let dbCache = null;
let dbCacheTime = 0;
const CACHE_TTL = 15000; // 15s

/**
 * Read entire database from JSONBin
 * Returns { users: [], messages: [], sessions: {} }
 */
async function readDB(forceRefresh = false) {
    if (!forceRefresh && dbCache && (Date.now() - dbCacheTime) < CACHE_TTL) {
        return dbCache;
    }
    try {
        const res = await axios.get(`${JSONBIN_BASE}/b/${JSONBIN_BIN_ID}/latest`, {
            headers: jsonbinHeaders,
            timeout: 12000
        });
        let data = res.data;
        if (data && data.record !== undefined) data = data.record;
        if (!data || typeof data !== 'object') {
            data = { users: [], messages: [], sessions: {} };
        }
        if (!Array.isArray(data.users)) data.users = [];
        if (!Array.isArray(data.messages)) data.messages = [];
        if (!data.sessions || typeof data.sessions !== 'object') data.sessions = {};

        dbCache = data;
        dbCacheTime = Date.now();
        return data;
    } catch (err) {
        console.error('❌ JSONBin read error:', err.response?.status || err.message);
        // Fallback to cache or empty structure
        if (dbCache) return dbCache;
        return { users: [], messages: [], sessions: {} };
    }
}

/**
 * Write entire database to JSONBin
 */
async function writeDB(data) {
    try {
        const res = await axios.put(`${JSONBIN_BASE}/b/${JSONBIN_BIN_ID}`, data, {
            headers: jsonbinHeaders,
            timeout: 12000
        });
        dbCache = data;
        dbCacheTime = Date.now();
        return true;
    } catch (err) {
        console.error('❌ JSONBin write error:', err.response?.status || err.message);
        // Still update local cache so UI works even if remote write fails
        dbCache = data;
        dbCacheTime = Date.now();
        return false;
    }
}

// ============================================================
//  UTILITIES
// ============================================================
function hashPin(pin) {
    return crypto.createHash('sha256').update('vertex:' + String(pin)).digest('hex');
}

function hashPassword(pw) {
    return crypto.createHash('sha256').update('vertex-pw:' + String(pw)).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(24).toString('hex');
}

function sanitizeUser(u) {
    if (!u) return null;
    const { pinHash, passwordHash, ...safe } = u;
    return safe;
}

function isValidUKPostcode(pc) {
    return /^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$/i.test((pc || '').trim());
}

function calcAge(dob) {
    if (!dob) return null;
    const d = new Date(dob);
    if (isNaN(d.getTime())) return null;
    const now = new Date();
    let age = now.getFullYear() - d.getFullYear();
    const m = now.getMonth() - d.getMonth();
    if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
    return age;
}

// ============================================================
//  AUTH MIDDLEWARE
// ============================================================
async function authUser(req, res, next) {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
        if (!token) return res.status(401).json({ message: 'No token provided' });

        const db = await readDB();
        const session = db.sessions[token];
        if (!session) return res.status(401).json({ message: 'Invalid or expired token' });

        const user = db.users.find(u => u.id === session.userId);
        if (!user) return res.status(401).json({ message: 'User not found' });

        req.user = user;
        req.token = token;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ message: 'Auth failure' });
    }
}

function authAdmin(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
    if (!token || !token.startsWith('admin:')) {
        return res.status(401).json({ message: 'Admin authentication required' });
    }
    // Simple admin token check
    const expected = 'admin:' + crypto.createHash('sha256').update(ADMIN_USER + ':' + ADMIN_PASS).digest('hex').slice(0, 32);
    if (token !== expected) {
        return res.status(401).json({ message: 'Invalid admin token' });
    }
    next();
}

// ============================================================
//  API ROUTES — HEALTH
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString(), service: 'Vertex Talent API' });
});

// ============================================================
//  API — REGISTRATION
// ============================================================
app.post('/api/register', upload.single('avatar'), async (req, res) => {
    try {
        const {
            firstName, lastName, email, phone, dob,
            addressLine1, city, postcode, jobType, pin
        } = req.body;

        // --- Validate required fields ---
        if (!firstName || !lastName || !email || !phone || !dob || !addressLine1 || !city || !postcode || !jobType || !pin) {
            return res.status(400).json({ message: 'All required fields must be filled.' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ message: 'Invalid email address.' });
        }
        if (!/^\d{6}$/.test(String(pin))) {
            return res.status(400).json({ message: 'PIN must be exactly 6 digits.' });
        }
        const weakPins = ['000000','111111','222222','333333','444444','555555','666666','777777','888888','999999','123456','654321','012345','987654'];
        if (weakPins.includes(String(pin))) {
            return res.status(400).json({ message: 'PIN too simple. Please choose another.' });
        }
        const age = calcAge(dob);
        if (age === null || age < 16 || age > 120) {
            return res.status(400).json({ message: 'You must be at least 16 years old.' });
        }
        if (!isValidUKPostcode(postcode)) {
            return res.status(400).json({ message: 'Invalid UK postcode.' });
        }

        const db = await readDB(true);
        const emailLower = email.toLowerCase().trim();
        if (db.users.some(u => (u.email || '').toLowerCase() === emailLower)) {
            return res.status(409).json({ message: 'An account with this email already exists.' });
        }

        // Build avatar URL
        let avatarUrl = null;
        if (req.file) {
            avatarUrl = '/uploads/' + req.file.filename;
        }

        // Create user
        const user = {
            id: 'u_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
            firstName: String(firstName).trim(),
            lastName: String(lastName).trim(),
            email: emailLower,
            phone: String(phone).trim(),
            dob,
            age,
            addressLine1: String(addressLine1).trim(),
            city: String(city).trim(),
            postcode: String(postcode).trim().toUpperCase(),
            address: `${addressLine1}, ${city}, ${postcode}`,
            jobType,
            avatarUrl,
            pinHash: hashPin(pin),
            passwordHash: hashPassword(pin), // fallback password = PIN
            role: 'candidate',
            status: 'active',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            lastLogin: null
        };

        db.users.push(user);

        // Create session
        const token = generateToken();
        db.sessions[token] = { userId: user.id, createdAt: Date.now(), type: 'user' };

        await writeDB(db);

        // Notify admin (internal message)
        db.messages.push({
            id: 'm_' + Date.now(),
            from: 'system',
            to: 'admin',
            subject: 'New user registered',
            body: `${user.firstName} ${user.lastName} (${user.email}) just joined as a ${user.jobType}.`,
            read: false,
            createdAt: new Date().toISOString()
        });
        await writeDB(db);

        res.status(201).json({
            message: 'Account created successfully!',
            user: sanitizeUser(user),
            token
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ message: 'Registration failed. Please try again.' });
    }
});

// ============================================================
//  API — LOGIN WITH PIN
// ============================================================
app.post('/api/login/pin', async (req, res) => {
    try {
        const { pin, email } = req.body;
        if (!pin || !/^\d{6}$/.test(String(pin))) {
            return res.status(400).json({ message: 'Please enter a valid 6-digit PIN.' });
        }

        const db = await readDB(true);
        const pinH = hashPin(pin);

        // Find user by PIN (if email provided, narrow down)
        let user = null;
        if (email) {
            user = db.users.find(u => u.email === email.toLowerCase().trim() && u.pinHash === pinH);
        } else {
            const matches = db.users.filter(u => u.pinHash === pinH);
            if (matches.length === 1) user = matches[0];
            else if (matches.length > 1) {
                return res.status(409).json({ message: 'Multiple accounts share this PIN. Please provide your email.' });
            }
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid PIN. Please try again.' });
        }
        if (user.status === 'suspended' || user.status === 'banned') {
            return res.status(403).json({ message: 'Account suspended. Contact support.' });
        }

        user.lastLogin = new Date().toISOString();
        const token = generateToken();
        db.sessions[token] = { userId: user.id, createdAt: Date.now(), type: 'user' };

        // Cleanup old sessions (older than 30 days)
        const cutoff = Date.now() - 30 * 86400000;
        Object.keys(db.sessions).forEach(t => {
            if (db.sessions[t].createdAt < cutoff) delete db.sessions[t];
        });

        await writeDB(db);

        res.json({
            message: 'Login successful',
            user: sanitizeUser(user),
            token
        });
    } catch (err) {
        console.error('PIN login error:', err);
        res.status(500).json({ message: 'Login failed. Please try again.' });
    }
});

// ============================================================
//  API — LOGIN WITH EMAIL + PASSWORD
// ============================================================
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password required.' });
        }

        const db = await readDB(true);
        const user = db.users.find(u => (u.email || '').toLowerCase() === email.toLowerCase().trim());

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        if (user.status === 'suspended' || user.status === 'banned') {
            return res.status(403).json({ message: 'Account suspended. Contact support.' });
        }

        const pwH = hashPassword(password);
        if (user.passwordHash !== pwH && user.pinHash !== pwH && user.pinHash !== hashPin(password)) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        user.lastLogin = new Date().toISOString();
        const token = generateToken();
        db.sessions[token] = { userId: user.id, createdAt: Date.now(), type: 'user' };
        await writeDB(db);

        res.json({ message: 'Login successful', user: sanitizeUser(user), token });
    } catch (err) {
        console.error('Email login error:', err);
        res.status(500).json({ message: 'Login failed.' });
    }
});

// ============================================================
//  API — GET CURRENT USER
// ============================================================
app.get('/api/me', authUser, (req, res) => {
    res.json({ user: sanitizeUser(req.user) });
});

// ============================================================
//  API — UPDATE PROFILE
// ============================================================
app.put('/api/profile', authUser, upload.single('avatar'), async (req, res) => {
    try {
        const db = await readDB(true);
        const user = db.users.find(u => u.id === req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const editable = ['firstName', 'lastName', 'phone', 'addressLine1', 'city', 'postcode', 'jobType'];
        editable.forEach(field => {
            if (req.body[field] !== undefined && req.body[field] !== '') {
                user[field] = String(req.body[field]).trim();
            }
        });

        if (req.body.addressLine1 || req.body.city || req.body.postcode) {
            user.address = `${user.addressLine1 || ''}, ${user.city || ''}, ${user.postcode || ''}`.replace(/^,\s*|,\s*$/g, '');
        }
        if (req.body.dob) {
            user.dob = req.body.dob;
            user.age = calcAge(req.body.dob);
        }
        if (req.file) {
            user.avatarUrl = '/uploads/' + req.file.filename;
        }
        user.updatedAt = new Date().toISOString();

        await writeDB(db);
        res.json({ message: 'Profile updated', user: sanitizeUser(user) });
    } catch (err) {
        console.error('Update profile error:', err);
        res.status(500).json({ message: 'Update failed' });
    }
});

// ============================================================
//  API — CHANGE PIN / PASSWORD (user)
// ============================================================
app.post('/api/change-pin', authUser, async (req, res) => {
    try {
        const { currentPin, newPin } = req.body;
        if (!currentPin || !newPin) return res.status(400).json({ message: 'Current and new PIN required' });
        if (!/^\d{6}$/.test(String(newPin))) return res.status(400).json({ message: 'New PIN must be 6 digits' });

        const db = await readDB(true);
        const user = db.users.find(u => u.id === req.user.id);
        if (hashPin(currentPin) !== user.pinHash) {
            return res.status(401).json({ message: 'Current PIN is incorrect' });
        }
        user.pinHash = hashPin(newPin);
        user.passwordHash = hashPassword(newPin);
        user.updatedAt = new Date().toISOString();
        await writeDB(db);
        res.json({ message: 'PIN updated successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Failed to change PIN' });
    }
});

// ============================================================
//  API — LOGOUT
// ============================================================
app.post('/api/logout', authUser, async (req, res) => {
    try {
        const db = await readDB(true);
        delete db.sessions[req.token];
        await writeDB(db);
        res.json({ message: 'Logged out' });
    } catch (err) {
        res.status(500).json({ message: 'Logout failed' });
    }
});

// ============================================================
//  API — JOBS (Remotive — free, no registration)
// ============================================================
// Remotive docs: https://remotive.com/api/remote-jobs
// Free, no API key. Supports search & category filtering.
app.get('/api/jobs', async (req, res) => {
    try {
        const { what = '', location = '', category = '', page = 1, results_per_page = 20, sort_by = 'relevance' } = req.query;

        // Build Remotive query
        const params = new URLSearchParams();
        if (what) params.set('search', what);
        if (category) params.set('category', category);
        params.set('limit', Math.min(parseInt(results_per_page) || 20, 50));

        const url = `https://remotive.com/api/remote-jobs?${params.toString()}`;
        const response = await axios.get(url, { timeout: 15000 });

        let jobs = (response.data?.jobs || []).map(job => ({
            id: String(job.id),
            title: job.title,
            company: { display_name: job.company_name || 'Company' },
            location: {
                display_name: job.candidate_required_location || 'Remote / UK'
            },
            salary_min: null,
            salary_max: null,
            salary_text: job.salary || null,
            contract_time: job.job_type || 'full_time',
            contract_type: job.job_type || 'full_time',
            created: job.publication_date,
            description: stripHtml(job.description || ''),
            redirect_url: job.url,
            url: job.url,
            category: job.category,
            tags: job.tags || [],
            logo: job.company_logo || null,
            source: 'Remotive'
        }));

        // Client-side filtering for location/type (Remotive doesn't support all params)
        if (location) {
            const locLower = location.toLowerCase();
            const filtered = jobs.filter(j =>
                (j.location.display_name || '').toLowerCase().includes(locLower) ||
                (j.location.display_name || '').toLowerCase().includes('worldwide') ||
                (j.location.display_name || '').toLowerCase().includes('anywhere')
            );
            // If no matches in location, keep remote roles (better UX)
            if (filtered.length > 0) jobs = filtered;
        }
        if (req.query.contract_time) {
            const ct = req.query.contract_time.toLowerCase();
            jobs = jobs.filter(j => (j.contract_time || '').toLowerCase().includes(ct) || (j.contract_type || '').toLowerCase().includes(ct));
        }

        // Sort
        if (sort_by === 'date') {
            jobs.sort((a, b) => new Date(b.created) - new Date(a.created));
        } else if (sort_by === 'salary') {
            jobs.sort((a, b) => (b.salary_max || 0) - (a.salary_max || 0));
        }

        // Paginate
        const p = Math.max(1, parseInt(page) || 1);
        const perPage = Math.min(parseInt(results_per_page) || 20, 50);
        const total = jobs.length;
        const paged = jobs.slice((p - 1) * perPage, p * perPage);

        res.json({
            count: total,
            page: p,
            results_per_page: perPage,
            results: paged,
            source: 'Remotive (free public API)'
        });
    } catch (err) {
        console.error('Jobs API error:', err.message);
        res.status(500).json({
            error: 'Could not fetch jobs',
            message: err.message,
            count: 0,
            results: []
        });
    }
});

function stripHtml(html) {
    return String(html || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

// ============================================================
//  API — MESSAGES (user ↔ admin)
// ============================================================

// User sends a message to admin
app.post('/api/messages', authUser, async (req, res) => {
    try {
        const { subject = 'Support request', body } = req.body;
        if (!body || !body.trim()) return res.status(400).json({ message: 'Message body required' });

        const db = await readDB(true);
        const msg = {
            id: 'm_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
            from: req.user.id,
            fromName: `${req.user.firstName} ${req.user.lastName}`,
            fromEmail: req.user.email,
            to: 'admin',
            subject: String(subject).slice(0, 120),
            body: String(body).slice(0, 5000),
            read: false,
            createdAt: new Date().toISOString()
        };
        db.messages.push(msg);
        await writeDB(db);
        res.status(201).json({ message: 'Message sent', data: msg });
    } catch (err) {
        console.error('Send message error:', err);
        res.status(500).json({ message: 'Failed to send message' });
    }
});

// Get all messages for current user (inbox + sent)
app.get('/api/messages', authUser, async (req, res) => {
    try {
        const db = await readDB();
        const inbox = db.messages.filter(m => m.to === req.user.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        const sent = db.messages.filter(m => m.from === req.user.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json({ inbox, sent });
    } catch (err) {
        res.status(500).json({ message: 'Failed to load messages' });
    }
});

// Mark message as read
app.post('/api/messages/:id/read', authUser, async (req, res) => {
    try {
        const db = await readDB(true);
        const msg = db.messages.find(m => m.id === req.params.id);
        if (!msg) return res.status(404).json({ message: 'Message not found' });
        if (msg.to !== req.user.id && msg.from !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized' });
        }
        msg.read = true;
        await writeDB(db);
        res.json({ message: 'Marked as read' });
    } catch (err) {
        res.status(500).json({ message: 'Failed' });
    }
});

// ============================================================
//  ADMIN API — LOGIN
// ============================================================
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && password === ADMIN_PASS) {
        const token = 'admin:' + crypto.createHash('sha256').update(username + ':' + password).digest('hex').slice(0, 32);
        return res.json({ message: 'Admin login successful', token, username: ADMIN_USER });
    }
    return res.status(401).json({ message: 'Invalid admin credentials' });
});

// ============================================================
//  ADMIN API — STATS
// ============================================================
app.get('/api/admin/stats', authAdmin, async (req, res) => {
    try {
        const db = await readDB(true);
        const totalUsers = db.users.length;
        const activeUsers = db.users.filter(u => u.status === 'active').length;
        const suspended = db.users.filter(u => u.status === 'suspended' || u.status === 'banned').length;
        const unreadMessages = db.messages.filter(m => m.to === 'admin' && !m.read).length;
        const today = new Date().toISOString().slice(0, 10);
        const newToday = db.users.filter(u => (u.createdAt || '').startsWith(today)).length;

        // Users by job type
        const byJobType = {};
        db.users.forEach(u => {
            const jt = u.jobType || 'Unknown';
            byJobType[jt] = (byJobType[jt] || 0) + 1;
        });

        res.json({
            totalUsers,
            activeUsers,
            suspended,
            unreadMessages,
            newToday,
            totalMessages: db.messages.length,
            activeSessions: Object.keys(db.sessions).length,
            byJobType
        });
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({ message: 'Failed to load stats' });
    }
});

// ============================================================
//  ADMIN API — LIST USERS
// ============================================================
app.get('/api/admin/users', authAdmin, async (req, res) => {
    try {
        const { search = '', status = '', jobType = '' } = req.query;
        const db = await readDB();

        let users = db.users.map(u => ({
            ...sanitizeUser(u),
            hasPin: !!u.pinHash
        }));

        if (search) {
            const s = search.toLowerCase();
            users = users.filter(u =>
                (u.firstName || '').toLowerCase().includes(s) ||
                (u.lastName || '').toLowerCase().includes(s) ||
                (u.email || '').toLowerCase().includes(s) ||
                (u.phone || '').toLowerCase().includes(s) ||
                (u.city || '').toLowerCase().includes(s)
            );
        }
        if (status) users = users.filter(u => u.status === status);
        if (jobType) users = users.filter(u => u.jobType === jobType);

        users.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        res.json({ total: users.length, users });
    } catch (err) {
        res.status(500).json({ message: 'Failed to load users' });
    }
});

// ============================================================
//  ADMIN API — GET SINGLE USER
// ============================================================
app.get('/api/admin/users/:id', authAdmin, async (req, res) => {
    try {
        const db = await readDB();
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ user: sanitizeUser(user), hasPin: !!user.pinHash });
    } catch (err) {
        res.status(500).json({ message: 'Failed' });
    }
});

// ============================================================
//  ADMIN API — UPDATE USER (profile, status, role)
// ============================================================
app.put('/api/admin/users/:id', authAdmin, async (req, res) => {
    try {
        const db = await readDB(true);
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const fields = ['firstName', 'lastName', 'email', 'phone', 'jobType', 'status', 'role', 'city', 'postcode', 'addressLine1'];
        fields.forEach(f => {
            if (req.body[f] !== undefined && req.body[f] !== '') user[f] = req.body[f];
        });
        if (req.body.addressLine1 || req.body.city || req.body.postcode) {
            user.address = `${user.addressLine1 || ''}, ${user.city || ''}, ${user.postcode || ''}`.replace(/^,\s*|,\s*$/g, '');
        }
        user.updatedAt = new Date().toISOString();

        await writeDB(db);
        res.json({ message: 'User updated', user: sanitizeUser(user) });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update user' });
    }
});

// ============================================================
//  ADMIN API — CHANGE USER PIN/PASSWORD
// ============================================================
app.post('/api/admin/users/:id/change-password', authAdmin, async (req, res) => {
    try {
        const { newPin, newPassword } = req.body;
        if (!newPin && !newPassword) return res.status(400).json({ message: 'New PIN or password required' });
        if (newPin && !/^\d{6}$/.test(String(newPin))) return res.status(400).json({ message: 'PIN must be 6 digits' });

        const db = await readDB(true);
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        if (newPin) {
            user.pinHash = hashPin(newPin);
            user.passwordHash = hashPassword(newPin);
        }
        if (newPassword) {
            user.passwordHash = hashPassword(newPassword);
        }
        user.updatedAt = new Date().toISOString();
        await writeDB(db);
        res.json({ message: 'Password/PIN updated successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update password' });
    }
});

// ============================================================
//  ADMIN API — TOGGLE STATUS (suspend/activate)
// ============================================================
app.post('/api/admin/users/:id/status', authAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        if (!['active', 'suspended', 'banned'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }
        const db = await readDB(true);
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        user.status = status;
        user.updatedAt = new Date().toISOString();

        // Force logout suspended users
        if (status !== 'active') {
            Object.keys(db.sessions).forEach(t => {
                if (db.sessions[t].userId === user.id) delete db.sessions[t];
            });
        }
        await writeDB(db);
        res.json({ message: `User ${status}`, user: sanitizeUser(user) });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update status' });
    }
});

// ============================================================
//  ADMIN API — DELETE USER
// ============================================================
app.delete('/api/admin/users/:id', authAdmin, async (req, res) => {
    try {
        const db = await readDB(true);
        const idx = db.users.findIndex(u => u.id === req.params.id);
        if (idx === -1) return res.status(404).json({ message: 'User not found' });

        const userId = db.users[idx].id;
        db.users.splice(idx, 1);
        db.messages = db.messages.filter(m => m.from !== userId && m.to !== userId);
        Object.keys(db.sessions).forEach(t => {
            if (db.sessions[t].userId === userId) delete db.sessions[t];
        });
        await writeDB(db);
        res.json({ message: 'User deleted permanently' });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete user' });
    }
});

// ============================================================
//  ADMIN API — MESSAGES
// ============================================================

// Get all messages (admin view)
app.get('/api/admin/messages', authAdmin, async (req, res) => {
    try {
        const { filter = 'all' } = req.query;
        const db = await readDB();

        let msgs = [...db.messages].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        if (filter === 'unread') msgs = msgs.filter(m => !m.read && m.to === 'admin');
        if (filter === 'from-users') msgs = msgs.filter(m => m.to === 'admin');
        if (filter === 'sent-by-admin') msgs = msgs.filter(m => m.from === 'admin');

        // Attach user info
        const usersMap = {};
        db.users.forEach(u => usersMap[u.id] = { firstName: u.firstName, lastName: u.lastName, email: u.email });

        msgs = msgs.map(m => ({
            ...m,
            fromUserName: m.from === 'admin' || m.from === 'system'
                ? (m.from === 'admin' ? 'Admin' : 'System')
                : (usersMap[m.from]?.firstName + ' ' + (usersMap[m.from]?.lastName || '') || 'Unknown'),
            toUserName: m.to === 'admin'
                ? 'Admin'
                : (usersMap[m.to]?.firstName + ' ' + (usersMap[m.to]?.lastName || '') || 'Unknown')
        }));

        res.json({ total: msgs.length, messages: msgs });
    } catch (err) {
        res.status(500).json({ message: 'Failed to load messages' });
    }
});

// Admin sends message to a user
app.post('/api/admin/messages', authAdmin, async (req, res) => {
    try {
        const { to, subject = 'Message from Vertex Talent', body } = req.body;
        if (!to || !body) return res.status(400).json({ message: 'Recipient and body required' });

        const db = await readDB(true);
        const targetUser = db.users.find(u => u.id === to || u.email === to);
        if (!targetUser) return res.status(404).json({ message: 'Recipient not found' });

        const msg = {
            id: 'm_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
            from: 'admin',
            fromName: 'Vertex Admin',
            fromEmail: 'admin@vertextalent.co.uk',
            to: targetUser.id,
            toName: `${targetUser.firstName} ${targetUser.lastName}`,
            subject: String(subject).slice(0, 120),
            body: String(body).slice(0, 5000),
            read: false,
            createdAt: new Date().toISOString()
        };
        db.messages.push(msg);
        await writeDB(db);
        res.status(201).json({ message: 'Message sent to user', data: msg });
    } catch (err) {
        res.status(500).json({ message: 'Failed to send message' });
    }
});

// Admin marks message read
app.post('/api/admin/messages/:id/read', authAdmin, async (req, res) => {
    try {
        const db = await readDB(true);
        const msg = db.messages.find(m => m.id === req.params.id);
        if (!msg) return res.status(404).json({ message: 'Not found' });
        msg.read = true;
        await writeDB(db);
        res.json({ message: 'Marked as read' });
    } catch (err) {
        res.status(500).json({ message: 'Failed' });
    }
});

// Admin deletes message
app.delete('/api/admin/messages/:id', authAdmin, async (req, res) => {
    try {
        const db = await readDB(true);
        db.messages = db.messages.filter(m => m.id !== req.params.id);
        await writeDB(db);
        res.json({ message: 'Message deleted' });
    } catch (err) {
        res.status(500).json({ message: 'Failed' });
    }
});

// ============================================================
//  ADMIN — FORCE LOGOUT USER
// ============================================================
app.post('/api/admin/users/:id/logout', authAdmin, async (req, res) => {
    try {
        const db = await readDB(true);
        Object.keys(db.sessions).forEach(t => {
            if (db.sessions[t].userId === req.params.id) delete db.sessions[t];
        });
        await writeDB(db);
        res.json({ message: 'User logged out from all sessions' });
    } catch (err) {
        res.status(500).json({ message: 'Failed' });
    }
});

// ============================================================
//  API — CONTACT / WHATSAPP CLICK TRACKING
// ============================================================
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        if (!name || !email || !message) return res.status(400).json({ message: 'All fields required' });

        const db = await readDB(true);
        db.messages.push({
            id: 'm_' + Date.now(),
            from: 'guest',
            fromName: String(name).slice(0, 80),
            fromEmail: String(email).slice(0, 120),
            to: 'admin',
            subject: 'Contact form submission',
            body: String(message).slice(0, 3000),
            read: false,
            createdAt: new Date().toISOString()
        });
        await writeDB(db);
        res.json({ message: 'Message received. We will reply soon.' });
    } catch (err) {
        res.status(500).json({ message: 'Failed to send' });
    }
});

// ============================================================
//  HTML PAGE ROUTES (serve from /public)
// ============================================================
const pages = ['index', 'register', 'login', 'dashboard', 'jobs', 'about', 'chat', 'profile', 'support', 'applications', 'saved', 'admin'];
pages.forEach(p => {
    app.get(`/${p === 'index' ? '' : p}`, (req, res, next) => {
        const file = path.join(__dirname, 'public', p + '.html');
        if (fs.existsSync(file)) res.sendFile(file);
        else next();
    });
});

// Root
app.get('/', (req, res) => {
    const file = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(file)) res.sendFile(file);
    else res.send('Vertex Talent API running. Create public/index.html to serve the site.');
});

// Admin page
app.get('/admin', (req, res) => {
    const file = path.join(__dirname, 'public', 'admin.html');
    if (fs.existsSync(file)) res.sendFile(file);
    else res.status(404).send('Admin panel not found. Create public/admin.html');
});

// 404 fallback
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ message: 'Endpoint not found' });
    }
    res.status(404).send('Page not found');
});

// Error handler (multer etc)
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.message);
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ message: 'Upload error: ' + err.message });
    }
    res.status(500).json({ message: err.message || 'Internal server error' });
});

// ============================================================
//  START
// ============================================================
app.listen(PORT, () => {
    console.log('\n' + '='.repeat(60));
    console.log('🚀 Vertex Talent Server running');
    console.log('   URL:      http://localhost:' + PORT);
    console.log('   Admin:    http://localhost:' + PORT + '/admin');
    console.log('   API:      http://localhost:' + PORT + '/api/health');
    console.log('   Database: JSONBin (bin ' + JSONBIN_BIN_ID.slice(0, 8) + '…)');
    console.log('   Jobs API: Remotive (free, no key)');
    console.log('='.repeat(60) + '\n');
});
