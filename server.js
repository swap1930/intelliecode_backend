const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const pgSession = require('connect-pg-simple')(session);
const axios = require('axios');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const http = require('http');
const { Server } = require('socket.io');
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: ['http://localhost:5173', 'https://intelliecode-frontend.onrender.com', 'https://intelliecode.netlify.app'],
        methods: ['GET', 'POST'],
        credentials: true,
        allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
    },
    transports: ['websocket', 'polling']
});

const PORT = process.env.PORT || 3001;

// PostgreSQL pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_WluZYsSPQb59@ep-still-resonance-a4jegljf-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(bodyParser.json());

// CORS setup for Netlify + Render
app.use(cors({
    origin: ['http://localhost:5173', 'https://intelliecode.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

// Session setup
app.use(session({
    store: new pgSession({
        pool,
        tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // ✅ HTTPS cookies in production
        httpOnly: true,
        sameSite: 'none', // ✅ Cross-origin for Netlify -> Render
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Debug middleware to check session
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    console.log('Session data:', req.session);
    next();
});

// DB init
const initDB = async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS "session" (
            "sid" varchar NOT NULL PRIMARY KEY,
            "sess" json NOT NULL,
            "expire" timestamp(6) NOT NULL
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS code_snippets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(255),
            language VARCHAR(50),
            code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS shared_codes (
            id SERIAL PRIMARY KEY,
            share_id VARCHAR(16) UNIQUE NOT NULL,
            code TEXT NOT NULL,
            language VARCHAR(10) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    console.log('DB initialized');
};
initDB();

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email`,
            [username, email, hashedPassword]
        );
        res.status(201).json({ message: 'User created', user: result.rows[0] });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Signup failed' });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });
        req.session.user = { id: user.id, username: user.username, email: user.email };
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ error: 'Session failed' });
            }
            res.json({ message: 'Login successful', user: req.session.user });
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true });
    });
});

// Session status endpoint
app.get('/session-status', (req, res) => {
    if (req.session.user) {
        return res.json({ loggedIn: true, user: req.session.user });
    }
    res.json({ loggedIn: false });
});

// Save code snippet
app.post('/save-snippet', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    const { title, language, code } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO code_snippets (user_id, title, language, code) VALUES ($1, $2, $3, $4) RETURNING *`,
            [req.session.user.id, title, language, code]
        );
        res.status(201).json({ snippet: result.rows[0] });
    } catch (err) {
        console.error('Save snippet error:', err);
        res.status(500).json({ error: 'Could not save snippet' });
    }
});

// Fetch user snippets
app.get('/snippets', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    try {
        const result = await pool.query(
            `SELECT * FROM code_snippets WHERE user_id = $1 ORDER BY created_at DESC`,
            [req.session.user.id]
        );
        res.json({ snippets: result.rows });
    } catch (err) {
        console.error('Fetch snippets error:', err);
        res.status(500).json({ error: 'Could not fetch snippets' });
    }
});

// Start server
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
