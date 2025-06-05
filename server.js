const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { GenerativeAI, GoogleGenerativeAI } = require('@google/generative-ai');
const crypto = require('crypto');
const pgSession = require('connect-pg-simple')(session);
const axios = require('axios');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io'); 
const http = require('http'); 

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: [
            'http://localhost:5173',
            'http://127.0.0.1:5173',
            'https://intelliecode.netlify.app',
            'https://intelliecode-frontend.onrender.com'
        ],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization']
    }
});


app.use(express.json());

// ✅ CORS for Express API
const corsOptions = {
    origin: [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'https://intelliecode.netlify.app',
        'https://intelliecode-frontend.onrender.com'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Optional but recommended for preflight requests
app.options('*', cors(corsOptions));

const PORT = process.env.PORT || 3001;

const JUDGE_API_URL = 'https://api.jdoodle.com/v1/execute';
const JUDGE_CLIENT_ID = '60305b399070f6bb0649414720f47639';
const JUDGE_SECRET_KEY = 'a1dab422b92ac1a25fddb31fac0e8e98451f73307684e39363e11c7a2caa9d07';

// Language mappings for JDoodle API
const languageMappings = {
    'c': 'c',
    'cpp': 'cpp',
    'py': 'python3',
    'java': 'java',
    'js': 'nodejs',
    'php': 'php',
    'go': 'go',
    'rb': 'ruby',
    'rs': 'rust',
    'swift': 'swift'
};

// Initialize Gemini API
const genAI = new GoogleGenerativeAI('AIzaSyDWj0gEOQyqHc4bJC8w_9A-5WJi-d6yyVg');

// CORS configuration
app.use(cors({
    origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Add request logging middleware   
// Add request logging middleware   
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

app.use(bodyParser.json());

// PostgreSQL configuration
const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_WluZYsSPQb59@ep-still-resonance-a4jegljf-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: {
        rejectUnauthorized: false,
    }
});

// Session configuration
app.use(session({
    store: new pgSession({
        pool: pool, // your already defined PostgreSQL pool
        tableName: 'session' // optional: default is 'session'
    }),
    secret: 'IntellieCode',
    resave: false,
    saveUninitialized: false,
   cookie: {
    secure: process.env.NODE_ENV === 'production',  
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    httpOnly: true
}

}));

app.post('/clear-session', (req, res) => {
    if (req.session.executionContext) {
        req.session.executionContext = null;
    }
    res.json({ success: true });
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to PostgreSQL database');
    release();
});

// Create users table if it doesn't exist
const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
`;

// Create code snippets table if it doesn't exist
const createSnippetsTableQuery = `
    CREATE TABLE IF NOT EXISTS code_snippets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title VARCHAR(255) NOT NULL,
        language VARCHAR(50) NOT NULL,
        code TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
`;

// Create shared codes table if it doesn't exist
const createSharedCodesTableQuery = `
    CREATE TABLE IF NOT EXISTS shared_codes (
        id SERIAL PRIMARY KEY,
        share_id VARCHAR(16) UNIQUE NOT NULL,
        code TEXT NOT NULL,
        language VARCHAR(10) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
`;

const createSessionTableQuery = `
    CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL PRIMARY KEY,
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL
    );
`;

const initDB = async () => {
    try {
        await pool.query(createUsersTableQuery);
        console.log('Users table created or already exists');
        await pool.query(createSnippetsTableQuery);
        console.log('Code snippets table created or already exists');
        await pool.query(createSharedCodesTableQuery);
        console.log('Shared codes table created or already exists');
        await pool.query(createSessionTableQuery);
        console.log('Session table created or already exists');
    } catch (err) {
        console.error('Error creating tables:', err);
    }
};

initDB();

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const emailResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (emailResult.rows.length > 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Securely hash password

        const query = `
            INSERT INTO users (username, email, password)
            VALUES ($1, $2, $3)
            RETURNING id, username, email
        `;
        const result = await pool.query(query, [username, email, hashedPassword]);

        res.status(201).json({
            message: 'User created successfully',
            user: result.rows[0],
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Error creating user' });
    }
});


// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const query = 'SELECT id, username, email, password FROM users WHERE email = $1';
        const result = await pool.query(query, [email]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = result.rows[0];

        const isMatch = await bcrypt.compare(password, user.password); // Compare hashed password
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
        };

        res.json({
            message: 'Login successful',
            user: req.session.user,
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.json({ success: true });
    });
});

// Check session status
app.get('/session-status', (req, res) => {
    if (req.session.user) {
        console.log('Session check: User is logged in', req.session.user);
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        console.log('Session check: User is not logged in');
        res.json({ loggedIn: false });
    }
});

// Save code snippet
app.post('/save-snippet', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'User not logged in' });
    }

    const { title, language, code } = req.body;
    const userId = req.session.user.id;

    try {
        const query = `
            INSERT INTO code_snippets (user_id, title, language, code)
            VALUES ($1, $2, $3, $4)
            RETURNING id, title, language, code, created_at
        `;
        const values = [userId, title, language, code];
        const result = await pool.query(query, values);

        console.log('Snippet saved:', result.rows[0]);

        res.status(201).json({
            message: 'Code snippet saved successfully',
            snippet: result.rows[0]
        });
    } catch (error) {
        console.error('Error saving code snippet:', error);
        res.status(500).json({
            error: 'Error saving code snippet',
            details: error.message
        });
    }
});

// Fetch snippets
app.get('/snippets', async (req, res) => {
    if (!req.session.user) {
        console.log('Snippets fetch failed: User not logged in');
        return res.status(401).json({ error: 'User not logged in' });
    }

    const userId = req.session.user.id;

    try {
        const query = `
            SELECT id, title, language, code, created_at
            FROM code_snippets
            WHERE user_id = $1
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query, [userId]);

      console.log(`Fetched ${result.rows.length} snippets for user ${userId}`);

        res.json({ snippets: result.rows });
    } catch (error) {
        console.error('Error fetching snippets:', error);
        res.status(500).json({
            error: 'Error fetching snippets',
            details: error.message
        });
    }
});

// Compile Endpoint
app.post('/compile', async (req, res) => {
    console.log('Received compile request:', req.body);

    try {
        const userLang = req.body.language?.toLowerCase();
        const script = req.body.script;
        const input = req.body.input || ''; // Default to empty string if no input provided

        if (!userLang || !script) {
            return res.status(400).json({ error: 'Language and script are required' });
        }

        const mapped = languageMappings[userLang];
        if (!mapped) {
            return res.status(400).json({ error: 'Unsupported language' });
        }

        console.log('Sending request to Piston API:', {
            language: mapped.language,
            version: mapped.version,
            files: [{
                name: main.${mapped.language},
                content: script
            }],
            stdin: input
        });

        const response = await fetch('http://localhost:2000/api/v2/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                language: mapped.language,
                version: mapped.version,
                files: [{
                    name: main.${mapped.language},
                    content: script
                }],
                stdin: input
            }),
        });

        console.log('Piston API response status:', response.status);
        const data = await response.json();
        console.log('Piston API response data:', data);

        if (!response.ok) {
            throw new Error(Piston API error: ${response.statusText});
        }

        // Ensure proper output formatting
        res.json({
            output: data.run.stdout || '',
            statusCode: data.run.code,
            memory: data.run.memory,
            cpuTime: data.run.time,
            error: data.run.stderr || null,
        });
    } catch (error) {
        console.error('Compilation error:', error);
        res.status(500).json({
            error: 'Compilation failed',
            details: error.message,
        });
    }
});

// AI Code Suggestion Endpoint
app.post('/ai-suggestion', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'User not logged in' });
    }

    const { code, prompt } = req.body;

    if (!code) {
        return res.status(400).json({ 
            error: 'Missing required fields',
            details: 'Code is required'
        });
    }

    try {
        // Get the generative model with timeout
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.0-flash",
            generationConfig: {
                maxOutputTokens: 2048,
                temperature: 0.7,
                topP: 0.8,
                topK: 40,
            }
        });

        // Create prompt
        const fullPrompt = prompt ? ${prompt}\n\n${code} : code;

        // Set timeout for the request
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Request timed out')), 30000); // 30 seconds timeout
        });

        // Generate content with timeout
        const generatePromise = model.generateContent(fullPrompt);
        const result = await Promise.race([generatePromise, timeoutPromise]);
        
        const response = await result.response;
        const text = response.text();

        res.json({
            suggestion: text
        });
    } catch (error) {
        console.error('AI suggestion error:', error);
        if (error.message === 'Request timed out') {
            res.status(504).json({
                error: 'Request timed out',
                details: 'The AI suggestion request took too long to complete. Please try again with a smaller code snippet.'
            });
        } else {
            res.status(500).json({
                error: 'Failed to generate AI suggestion',
                details: error.message
            });
        }
    }
});

// Execute code endpoint (REST, fallback)
app.post('/execute', async (req, res) => {
    try {
        const { code, language, input, isFirstRun } = req.body;
        console.log('Execute request received:', { 
            code: code.substring(0, 100) + '...', 
            language,
            input: input || '',
            isFirstRun
        });

        if (!code || !language) {
            console.error('Missing required fields:', { code: !!code, language: !!language });
            return res.status(400).json({ 
                error: 'Missing required fields',
                details: 'Code and language are required'
            });
        }

        // Check if code requires input
        const requiresInput = isFirstRun && (
            code.includes('scanf') || 
            code.includes('cin') || 
            code.includes('input(') || 
            code.includes('readline') || 
            code.includes('gets') || 
            code.includes('fgets')
        );

        if (requiresInput && !input) {
            return res.json({
                requiresInput: true,
                prompt: 'Enter input: '
            });
        }

        // Create submission with input
        const createResponse = await axios.post(${JUDGE_API_URL}/submissions?base64_encoded=true, {
            source_code: Buffer.from(code).toString('base64'),
            language_id: languageMappings[language.toLowerCase()],
            stdin: Buffer.from(input || '').toString('base64'),
            cpu_time_limit: 5,
            memory_limit: 128000,
            stack_limit: 128000,
            max_processes_and_or_threads: 60,
            enable_network: false,
            wait: true,
            fields: '*'
        }, {
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-Token': JUDGE_SECRET_KEY,
                'X-Auth-User': JUDGE_CLIENT_ID
            }
        });

        if (!createResponse.data) {
            console.error('Failed to create submission:', createResponse.data);
            throw new Error('Failed to create submission');
        }

        // Format response
        let output = '';
        let error = '';

        if (createResponse.data.stdout) {
            output = Buffer.from(createResponse.data.stdout, 'base64').toString();
        }
        if (createResponse.data.stderr) {
            error = Buffer.from(createResponse.data.stderr, 'base64').toString();
        }

        // For C code with scanf, we need to handle the output differently
        if (language.toLowerCase() === 'c' && code.includes('scanf')) {
            if (isFirstRun) {
                // Get only the prompt before scanf
                const lines = output.split('\n');
                output = lines[0];
            } else {
                // For subsequent runs, get all output
                output = output.trim();
            }
        }

        const response = {
            output: output.trim(),
            error: error.trim(),
            status: createResponse.data.status?.description || 'Completed',
            time: createResponse.data.time || 0,
            memory: createResponse.data.memory || 0,
            requiresInput: false
        };

        console.log('Sending response:', response);
        res.json(response);

    } catch (error) {
        console.error('Judge API error:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to execute code',
            details: error.response?.data?.message || error.message || 'An unexpected error occurred'
        });
    }
});

// Generate shareable link
app.post('/generate-share-link', async (req, res) => {
    try {
        const { code, language } = req.body;
        
        // Generate a unique ID for the shared code
        const shareId = crypto.randomBytes(8).toString('hex');
        
        // Store the code in the database
        const result = await pool.query(
            'INSERT INTO shared_codes (share_id, code, language) VALUES ($1, $2, $3) RETURNING share_id',
            [shareId, code, language]
        );

        // Generate the shareable URL
      const shareUrl = https://intelliecode-frontend.onrender.com/share/${shareId};

        
        res.json({ shareUrl });
    } catch (error) {
        console.error('Error generating share link:', error);
        res.status(500).json({ error: 'Failed to generate share link' });
    }
});

// Get shared code
app.get('/shared-code/:shareId', async (req, res) => {
    try {
        const { shareId } = req.params;
        
        const result = await pool.query(
            'SELECT code, language FROM shared_codes WHERE share_id = $1',
            [shareId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Code not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching shared code:', error);
        res.status(500).json({ error: 'Failed to fetch shared code' });
    }
});

// Socket.io real-time code execution
io.on('connection', (socket) => {
    console.log('User connected for real-time code execution:', socket.id);

    socket.on('execute_code', async ({ code, language }) => {
        console.log('Received code execution request:', { 
            language,
            codeLength: code.length,
            codePreview: code.substring(0, 100) + '...'
        });
        
        try {
            if (!code || !language) {
                console.log('Missing fields:', { code: !!code, language: !!language });
                socket.emit('execution_error', { error: 'Missing required fields' });
                return;
            }

            // Create submission
            console.log('Creating submission with JDoodle...');
            const response = await axios.post(JUDGE_API_URL, {
                clientId: JUDGE_CLIENT_ID,
                clientSecret: JUDGE_SECRET_KEY,
                script: code,
                language: languageMappings[language.toLowerCase()],
                stdin: '',
                versionIndex: '0'
            }, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            console.log('JDoodle API Response:', response.data);

            if (response.data.output) {
                console.log('Sending output to client:', response.data.output);
                socket.emit('execution_result', { 
                    output: response.data.output,
                    error: '',
                    status: 'Completed',
                    time: response.data.cpuTime || 0,
                    memory: response.data.memory || 0
                });
            } else if (response.data.error) {
                console.log('Sending error to client:', response.data.error);
                socket.emit('execution_error', { error: response.data.error });
            } else {
                console.log('No output or error received');
                socket.emit('execution_result', { 
                    output: 'Program executed successfully but produced no output.',
                    error: '',
                    status: 'Completed',
                    time: 0,
                    memory: 0
                });
            }

        } catch (error) {
            console.error('Error executing code:', error);
            console.error('Error details:', error.response?.data || error.message);
            socket.emit('execution_error', { 
                error: 'Failed to execute code',
                details: error.response?.data?.message || error.message
            });
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected from real-time code execution:', socket.id);
    });
});


// Socket.io connection handler
io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});
server.listen(PORT, () => {
    console.log(Server running on port ${PORT});
});
