require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

const app = express();

// Environment variables
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const DATABASE_URL = process.env.DATABASE_URL;
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';

// PostgreSQL connection
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: false
});

// Middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// File upload configuration
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const userDir = path.join(UPLOAD_DIR, 'projects', req.user?.id?.toString() || 'temp');
        await fs.mkdir(userDir, { recursive: true });
        cb(null, userDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage,
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// ==================== DATABASE INITIALIZATION ====================

async function initDatabase() {
    const client = await pool.connect();
    try {
        await client.query(`
            -- Users table
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                display_name VARCHAR(100),
                avatar_url TEXT,
                bio TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT true,
                prefs JSONB DEFAULT '{}'::jsonb
            );

            -- Projects table
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                thumbnail_url TEXT,
                project_data JSONB,
                visibility VARCHAR(20) DEFAULT 'private' CHECK (visibility IN ('private', 'public', 'unlisted')),
                tags TEXT[],
                version INTEGER DEFAULT 1,
                fork_of INTEGER REFERENCES projects(id) ON DELETE SET NULL,
                stars_count INTEGER DEFAULT 0,
                views_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Project collaborators (for shared projects)
            CREATE TABLE IF NOT EXISTS project_collaborators (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                permission VARCHAR(20) DEFAULT 'view' CHECK (permission IN ('view', 'edit', 'admin')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, user_id)
            );

            -- Project stars (likes)
            CREATE TABLE IF NOT EXISTS project_stars (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, user_id)
            );

            -- Project comments
            CREATE TABLE IF NOT EXISTS project_comments (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                parent_id INTEGER REFERENCES project_comments(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Project versions (for version history)
            CREATE TABLE IF NOT EXISTS project_versions (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                version_number INTEGER NOT NULL,
                project_data JSONB,
                commit_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
            );

            -- Assets table (for project files like images)
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                filename VARCHAR(255) NOT NULL,
                original_name VARCHAR(255),
                mime_type VARCHAR(100),
                file_size INTEGER,
                file_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- User follows
            CREATE TABLE IF NOT EXISTS user_follows (
                id SERIAL PRIMARY KEY,
                follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(follower_id, following_id)
            );

            -- Activity log
            CREATE TABLE IF NOT EXISTS activity_log (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                action VARCHAR(50) NOT NULL,
                entity_type VARCHAR(50),
                entity_id INTEGER,
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id);
            CREATE INDEX IF NOT EXISTS idx_projects_visibility ON projects(visibility);
            CREATE INDEX IF NOT EXISTS idx_projects_tags ON projects USING GIN(tags);
            CREATE INDEX IF NOT EXISTS idx_projects_created ON projects(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_collaborators_user ON project_collaborators(user_id);
            CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id);
        `);
        
        // Migration: Add prefs column if not exists
        await client.query(`
            ALTER TABLE users ADD COLUMN IF NOT EXISTS prefs JSONB DEFAULT '{}'::jsonb;
        `);
        
        console.log('Database initialized successfully');
    } finally {
        client.release();
    }
}

// ==================== AUTHENTICATION MIDDLEWARE ====================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

function optionalAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                req.user = user;
            }
            next();
        });
    } else {
        next();
    }
}

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, displayName } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email and password are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO users (username, email, password_hash, display_name)
             VALUES ($1, $2, $3, $4)
             RETURNING id, username, email, display_name, created_at`,
            [username.toLowerCase(), email.toLowerCase(), passwordHash, displayName || username]
        );

        const user = result.rows[0];
        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Log activity
        await pool.query(
            `INSERT INTO activity_log (user_id, action, entity_type, entity_id)
             VALUES ($1, 'register', 'user', $1)`,
            [user.id]
        );

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                displayName: user.display_name
            },
            token
        });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ error: 'Username or email already exists' });
        }
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { login, password } = req.body;

        if (!login || !password) {
            return res.status(400).json({ error: 'Login and password are required' });
        }

        const result = await pool.query(
            `SELECT id, username, email, password_hash, display_name, avatar_url, is_active
             FROM users WHERE username = $1 OR email = $1`,
            [login.toLowerCase()]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        if (!user.is_active) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        await pool.query(
            `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1`,
            [user.id]
        );

        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                displayName: user.display_name,
                avatarUrl: user.avatar_url
            },
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, username, email, display_name, avatar_url, bio, created_at
             FROM users WHERE id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = result.rows[0];
        
        // Get user stats
        const stats = await pool.query(
            `SELECT 
                (SELECT COUNT(*) FROM projects WHERE owner_id = $1) as projects_count,
                (SELECT COUNT(*) FROM project_stars ps JOIN projects p ON ps.project_id = p.id WHERE p.owner_id = $1) as total_stars,
                (SELECT COUNT(*) FROM user_follows WHERE following_id = $1) as followers_count,
                (SELECT COUNT(*) FROM user_follows WHERE follower_id = $1) as following_count`,
            [req.user.id]
        );

        res.json({
            ...user,
            displayName: user.display_name,
            avatarUrl: user.avatar_url,
            stats: stats.rows[0]
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const { displayName, bio, avatarUrl } = req.body;

        const result = await pool.query(
            `UPDATE users 
             SET display_name = COALESCE($1, display_name),
                 bio = COALESCE($2, bio),
                 avatar_url = COALESCE($3, avatar_url),
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $4
             RETURNING id, username, email, display_name, avatar_url, bio`,
            [displayName, bio, avatarUrl, req.user.id]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// ==================== PROJECT ROUTES ====================

// Create project
app.post('/api/projects', authenticateToken, async (req, res) => {
    try {
        const { name, description, projectData, visibility, tags, thumbnail } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'Project name is required' });
        }

        const result = await pool.query(
            `INSERT INTO projects (owner_id, name, description, project_data, visibility, tags, thumbnail_url)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [req.user.id, name, description, projectData, visibility || 'private', tags || [], thumbnail]
        );

        // Log activity
        await pool.query(
            `INSERT INTO activity_log (user_id, action, entity_type, entity_id)
             VALUES ($1, 'create', 'project', $2)`,
            [req.user.id, result.rows[0].id]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Create project error:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// Get user's projects
app.get('/api/projects', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20, sort = 'updated_at', order = 'DESC' } = req.query;
        const offset = (page - 1) * limit;

        const validSorts = ['created_at', 'updated_at', 'name', 'stars_count', 'views_count'];
        const sortColumn = validSorts.includes(sort) ? sort : 'updated_at';
        const sortOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const result = await pool.query(
            `SELECT p.*, u.username as owner_username, u.display_name as owner_display_name
             FROM projects p
             JOIN users u ON p.owner_id = u.id
             WHERE p.owner_id = $1
             ORDER BY p.${sortColumn} ${sortOrder}
             LIMIT $2 OFFSET $3`,
            [req.user.id, limit, offset]
        );

        const countResult = await pool.query(
            `SELECT COUNT(*) FROM projects WHERE owner_id = $1`,
            [req.user.id]
        );

        res.json({
            projects: result.rows,
            total: parseInt(countResult.rows[0].count),
            page: parseInt(page),
            totalPages: Math.ceil(countResult.rows[0].count / limit)
        });
    } catch (error) {
        console.error('Get projects error:', error);
        res.status(500).json({ error: 'Failed to get projects' });
    }
});

// Get shared projects (projects shared with user)
app.get('/api/projects/shared', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT p.*, u.username as owner_username, u.display_name as owner_display_name,
                    pc.permission
             FROM projects p
             JOIN users u ON p.owner_id = u.id
             JOIN project_collaborators pc ON p.id = pc.project_id
             WHERE pc.user_id = $1
             ORDER BY p.updated_at DESC`,
            [req.user.id]
        );

        res.json({ projects: result.rows });
    } catch (error) {
        console.error('Get shared projects error:', error);
        res.status(500).json({ error: 'Failed to get shared projects' });
    }
});

// Get public/explore projects
app.get('/api/projects/explore', optionalAuth, async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 20, 
            sort = 'stars_count', 
            order = 'DESC',
            tag,
            search 
        } = req.query;
        const offset = (page - 1) * limit;

        let query = `
            SELECT p.*, u.username as owner_username, u.display_name as owner_display_name
            FROM projects p
            JOIN users u ON p.owner_id = u.id
            WHERE p.visibility = 'public'
        `;
        const params = [];
        let paramIndex = 1;

        if (tag) {
            query += ` AND $${paramIndex} = ANY(p.tags)`;
            params.push(tag);
            paramIndex++;
        }

        if (search) {
            query += ` AND (p.name ILIKE $${paramIndex} OR p.description ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }

        const validSorts = ['created_at', 'updated_at', 'name', 'stars_count', 'views_count'];
        const sortColumn = validSorts.includes(sort) ? sort : 'stars_count';
        const sortOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        query += ` ORDER BY p.${sortColumn} ${sortOrder} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        params.push(limit, offset);

        const result = await pool.query(query, params);

        // Get total count
        let countQuery = `SELECT COUNT(*) FROM projects p WHERE visibility = 'public'`;
        const countParams = [];
        let countParamIndex = 1;

        if (tag) {
            countQuery += ` AND $${countParamIndex} = ANY(p.tags)`;
            countParams.push(tag);
            countParamIndex++;
        }

        if (search) {
            countQuery += ` AND (p.name ILIKE $${countParamIndex} OR p.description ILIKE $${countParamIndex})`;
            countParams.push(`%${search}%`);
        }

        const countResult = await pool.query(countQuery, countParams);

        res.json({
            projects: result.rows,
            total: parseInt(countResult.rows[0].count),
            page: parseInt(page),
            totalPages: Math.ceil(countResult.rows[0].count / limit)
        });
    } catch (error) {
        console.error('Explore projects error:', error);
        res.status(500).json({ error: 'Failed to get projects' });
    }
});

// Get single project
app.get('/api/projects/:id', optionalAuth, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `SELECT p.*, u.username as owner_username, u.display_name as owner_display_name,
                    u.avatar_url as owner_avatar
             FROM projects p
             JOIN users u ON p.owner_id = u.id
             WHERE p.id = $1`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const project = result.rows[0];

        // Check access
        const isOwner = req.user && project.owner_id === req.user.id;
        let hasAccess = isOwner || project.visibility === 'public' || project.visibility === 'unlisted';

        if (!hasAccess && req.user) {
            // Check if user is a collaborator
            const collabResult = await pool.query(
                `SELECT permission FROM project_collaborators 
                 WHERE project_id = $1 AND user_id = $2`,
                [id, req.user.id]
            );
            hasAccess = collabResult.rows.length > 0;
            if (hasAccess) {
                project.userPermission = collabResult.rows[0].permission;
            }
        }

        if (!hasAccess) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Increment view count (only for non-owners)
        if (!isOwner) {
            await pool.query(
                `UPDATE projects SET views_count = views_count + 1 WHERE id = $1`,
                [id]
            );
        }

        // Check if user has starred
        if (req.user) {
            const starResult = await pool.query(
                `SELECT 1 FROM project_stars WHERE project_id = $1 AND user_id = $2`,
                [id, req.user.id]
            );
            project.hasStarred = starResult.rows.length > 0;
        }

        project.isOwner = isOwner;

        res.json(project);
    } catch (error) {
        console.error('Get project error:', error);
        res.status(500).json({ error: 'Failed to get project' });
    }
});

// Update project
app.put('/api/projects/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, projectData, visibility, tags, thumbnail, commitMessage } = req.body;

        // Check ownership or edit permission
        const accessResult = await pool.query(
            `SELECT p.owner_id, pc.permission
             FROM projects p
             LEFT JOIN project_collaborators pc ON p.id = pc.project_id AND pc.user_id = $2
             WHERE p.id = $1`,
            [id, req.user.id]
        );

        if (accessResult.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const { owner_id, permission } = accessResult.rows[0];
        const canEdit = owner_id === req.user.id || permission === 'edit' || permission === 'admin';

        if (!canEdit) {
            return res.status(403).json({ error: 'You do not have permission to edit this project' });
        }

        // Save current version if project_data is being updated
        if (projectData) {
            const currentProject = await pool.query(
                `SELECT project_data, version FROM projects WHERE id = $1`,
                [id]
            );
            
            if (currentProject.rows[0].project_data) {
                await pool.query(
                    `INSERT INTO project_versions (project_id, version_number, project_data, commit_message, created_by)
                     VALUES ($1, $2, $3, $4, $5)`,
                    [id, currentProject.rows[0].version, currentProject.rows[0].project_data, commitMessage || 'Auto-save', req.user.id]
                );
            }
        }

        const result = await pool.query(
            `UPDATE projects 
             SET name = COALESCE($1, name),
                 description = COALESCE($2, description),
                 project_data = COALESCE($3, project_data),
                 visibility = COALESCE($4, visibility),
                 tags = COALESCE($5, tags),
                 thumbnail_url = COALESCE($6, thumbnail_url),
                 version = version + 1,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $7
             RETURNING *`,
            [name, description, projectData, visibility, tags, thumbnail, id]
        );

        // Log activity
        await pool.query(
            `INSERT INTO activity_log (user_id, action, entity_type, entity_id)
             VALUES ($1, 'update', 'project', $2)`,
            [req.user.id, id]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Update project error:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// Delete project
app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `DELETE FROM projects WHERE id = $1 AND owner_id = $2 RETURNING id`,
            [id, req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found or access denied' });
        }

        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Delete project error:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

// Fork project
app.post('/api/projects/:id/fork', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Get original project
        const original = await pool.query(
            `SELECT * FROM projects WHERE id = $1 AND (visibility = 'public' OR owner_id = $2)`,
            [id, req.user.id]
        );

        if (original.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found or not accessible' });
        }

        const project = original.rows[0];

        // Create fork
        const result = await pool.query(
            `INSERT INTO projects (owner_id, name, description, project_data, visibility, tags, fork_of)
             VALUES ($1, $2, $3, $4, 'private', $5, $6)
             RETURNING *`,
            [req.user.id, `${project.name} (Fork)`, project.description, project.project_data, project.tags, id]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Fork project error:', error);
        res.status(500).json({ error: 'Failed to fork project' });
    }
});

// ==================== COLLABORATION ROUTES ====================

// Add collaborator
app.post('/api/projects/:id/collaborators', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { username, permission } = req.body;

        // Check ownership
        const project = await pool.query(
            `SELECT owner_id FROM projects WHERE id = $1`,
            [id]
        );

        if (project.rows.length === 0 || project.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Only project owner can add collaborators' });
        }

        // Find user
        const user = await pool.query(
            `SELECT id FROM users WHERE username = $1`,
            [username.toLowerCase()]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userId = user.rows[0].id;

        if (userId === req.user.id) {
            return res.status(400).json({ error: 'Cannot add yourself as collaborator' });
        }

        const result = await pool.query(
            `INSERT INTO project_collaborators (project_id, user_id, permission)
             VALUES ($1, $2, $3)
             ON CONFLICT (project_id, user_id) DO UPDATE SET permission = $3
             RETURNING *`,
            [id, userId, permission || 'view']
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Add collaborator error:', error);
        res.status(500).json({ error: 'Failed to add collaborator' });
    }
});

// Get collaborators
app.get('/api/projects/:id/collaborators', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `SELECT pc.*, u.username, u.display_name, u.avatar_url
             FROM project_collaborators pc
             JOIN users u ON pc.user_id = u.id
             WHERE pc.project_id = $1`,
            [id]
        );

        res.json({ collaborators: result.rows });
    } catch (error) {
        console.error('Get collaborators error:', error);
        res.status(500).json({ error: 'Failed to get collaborators' });
    }
});

// Remove collaborator
app.delete('/api/projects/:id/collaborators/:userId', authenticateToken, async (req, res) => {
    try {
        const { id, userId } = req.params;

        // Check ownership
        const project = await pool.query(
            `SELECT owner_id FROM projects WHERE id = $1`,
            [id]
        );

        if (project.rows.length === 0 || project.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Only project owner can remove collaborators' });
        }

        await pool.query(
            `DELETE FROM project_collaborators WHERE project_id = $1 AND user_id = $2`,
            [id, userId]
        );

        res.json({ message: 'Collaborator removed' });
    } catch (error) {
        console.error('Remove collaborator error:', error);
        res.status(500).json({ error: 'Failed to remove collaborator' });
    }
});

// ==================== STAR ROUTES ====================

// Star project
app.post('/api/projects/:id/star', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        await pool.query(
            `INSERT INTO project_stars (project_id, user_id)
             VALUES ($1, $2)
             ON CONFLICT (project_id, user_id) DO NOTHING`,
            [id, req.user.id]
        );

        await pool.query(
            `UPDATE projects SET stars_count = (
                SELECT COUNT(*) FROM project_stars WHERE project_id = $1
             ) WHERE id = $1`,
            [id]
        );

        res.json({ message: 'Project starred' });
    } catch (error) {
        console.error('Star project error:', error);
        res.status(500).json({ error: 'Failed to star project' });
    }
});

// Unstar project
app.delete('/api/projects/:id/star', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        await pool.query(
            `DELETE FROM project_stars WHERE project_id = $1 AND user_id = $2`,
            [id, req.user.id]
        );

        await pool.query(
            `UPDATE projects SET stars_count = (
                SELECT COUNT(*) FROM project_stars WHERE project_id = $1
             ) WHERE id = $1`,
            [id]
        );

        res.json({ message: 'Project unstarred' });
    } catch (error) {
        console.error('Unstar project error:', error);
        res.status(500).json({ error: 'Failed to unstar project' });
    }
});

// Get user's starred projects
app.get('/api/users/:username/starred', optionalAuth, async (req, res) => {
    try {
        const { username } = req.params;

        const result = await pool.query(
            `SELECT p.*, u.username as owner_username, u.display_name as owner_display_name
             FROM projects p
             JOIN users u ON p.owner_id = u.id
             JOIN project_stars ps ON p.id = ps.project_id
             JOIN users su ON ps.user_id = su.id
             WHERE su.username = $1 AND (p.visibility = 'public' OR p.owner_id = $2)
             ORDER BY ps.created_at DESC`,
            [username.toLowerCase(), req.user?.id]
        );

        res.json({ projects: result.rows });
    } catch (error) {
        console.error('Get starred error:', error);
        res.status(500).json({ error: 'Failed to get starred projects' });
    }
});

// ==================== VERSION HISTORY ====================

// Get project versions
app.get('/api/projects/:id/versions', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `SELECT pv.id, pv.version_number, pv.commit_message, pv.created_at,
                    u.username as created_by_username
             FROM project_versions pv
             LEFT JOIN users u ON pv.created_by = u.id
             WHERE pv.project_id = $1
             ORDER BY pv.version_number DESC`,
            [id]
        );

        res.json({ versions: result.rows });
    } catch (error) {
        console.error('Get versions error:', error);
        res.status(500).json({ error: 'Failed to get versions' });
    }
});

// Restore version
app.post('/api/projects/:id/versions/:versionId/restore', authenticateToken, async (req, res) => {
    try {
        const { id, versionId } = req.params;

        // Check ownership
        const project = await pool.query(
            `SELECT owner_id FROM projects WHERE id = $1`,
            [id]
        );

        if (project.rows.length === 0 || project.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Only project owner can restore versions' });
        }

        const version = await pool.query(
            `SELECT project_data FROM project_versions WHERE id = $1 AND project_id = $2`,
            [versionId, id]
        );

        if (version.rows.length === 0) {
            return res.status(404).json({ error: 'Version not found' });
        }

        // Save current as new version before restoring
        const current = await pool.query(
            `SELECT project_data, version FROM projects WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO project_versions (project_id, version_number, project_data, commit_message, created_by)
             VALUES ($1, $2, $3, 'Before restore', $4)`,
            [id, current.rows[0].version, current.rows[0].project_data, req.user.id]
        );

        // Restore
        const result = await pool.query(
            `UPDATE projects 
             SET project_data = $1, version = version + 1, updated_at = CURRENT_TIMESTAMP
             WHERE id = $2
             RETURNING *`,
            [version.rows[0].project_data, id]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Restore version error:', error);
        res.status(500).json({ error: 'Failed to restore version' });
    }
});

// ==================== ASSET UPLOAD ====================

// Upload asset
app.post('/api/projects/:id/assets', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const { id } = req.params;

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Check project access
        const project = await pool.query(
            `SELECT owner_id FROM projects WHERE id = $1`,
            [id]
        );

        if (project.rows.length === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const result = await pool.query(
            `INSERT INTO assets (project_id, owner_id, filename, original_name, mime_type, file_size, file_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [id, req.user.id, req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, req.file.path]
        );

        res.status(201).json({
            ...result.rows[0],
            url: `/api/assets/${result.rows[0].id}`
        });
    } catch (error) {
        console.error('Upload asset error:', error);
        res.status(500).json({ error: 'Failed to upload asset' });
    }
});

// Get asset
app.get('/api/assets/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `SELECT * FROM assets WHERE id = $1`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Asset not found' });
        }

        const asset = result.rows[0];
        res.sendFile(path.resolve(asset.file_path));
    } catch (error) {
        console.error('Get asset error:', error);
        res.status(500).json({ error: 'Failed to get asset' });
    }
});

// ==================== USER PREFERENCES ====================

// Get user preferences
app.get('/api/user/prefs', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT prefs FROM users WHERE id = $1', [req.user.id]);
        res.json(result.rows[0].prefs || {});
    } catch (error) {
        console.error('Get prefs error:', error);
        res.status(500).json({ error: 'Failed to get preferences' });
    }
});

// Save user preferences
// PUT /api/user/prefs
app.put('/api/user/prefs', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'UPDATE users SET prefs = $1 WHERE id = $2',
            [JSON.stringify(req.body), req.user.id]
        );
        res.json({ success: true, prefs: req.body });
    } catch (error) {
        console.error('Save prefs error:', error);
        res.status(500).json({ error: 'Failed to save preferences' });
    }
});

// POST da kabul et (client uyumluluğu için)
app.post('/api/user/prefs', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'UPDATE users SET prefs = $1 WHERE id = $2',
            [JSON.stringify(req.body), req.user.id]
        );
        res.json({ success: true, prefs: req.body });
    } catch (error) {
        console.error('Save prefs error:', error);
        res.status(500).json({ error: 'Failed to save preferences' });
    }
});

// ==================== USER PROFILE ====================

// Get user profile
app.get('/api/users/:username', optionalAuth, async (req, res) => {
    try {
        const { username } = req.params;

        const result = await pool.query(
            `SELECT id, username, display_name, avatar_url, bio, created_at
             FROM users WHERE username = $1`,
            [username.toLowerCase()]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = result.rows[0];

        // Get stats
        const stats = await pool.query(
            `SELECT 
                (SELECT COUNT(*) FROM projects WHERE owner_id = $1 AND visibility = 'public') as public_projects,
                (SELECT COUNT(*) FROM project_stars ps JOIN projects p ON ps.project_id = p.id WHERE p.owner_id = $1) as total_stars,
                (SELECT COUNT(*) FROM user_follows WHERE following_id = $1) as followers,
                (SELECT COUNT(*) FROM user_follows WHERE follower_id = $1) as following`,
            [user.id]
        );

        // Check if current user follows this user
        let isFollowing = false;
        if (req.user && req.user.id !== user.id) {
            const followResult = await pool.query(
                `SELECT 1 FROM user_follows WHERE follower_id = $1 AND following_id = $2`,
                [req.user.id, user.id]
            );
            isFollowing = followResult.rows.length > 0;
        }

        res.json({
            ...user,
            displayName: user.display_name,
            avatarUrl: user.avatar_url,
            stats: stats.rows[0],
            isFollowing
        });
    } catch (error) {
        console.error('Get user profile error:', error);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

// Get user's public projects
app.get('/api/users/:username/projects', optionalAuth, async (req, res) => {
    try {
        const { username } = req.params;

        const user = await pool.query(
            `SELECT id FROM users WHERE username = $1`,
            [username.toLowerCase()]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userId = user.rows[0].id;
        const isOwnProfile = req.user && req.user.id === userId;

        let query = `
            SELECT p.*, u.username as owner_username, u.display_name as owner_display_name
            FROM projects p
            JOIN users u ON p.owner_id = u.id
            WHERE p.owner_id = $1
        `;

        if (!isOwnProfile) {
            query += ` AND p.visibility = 'public'`;
        }

        query += ` ORDER BY p.updated_at DESC`;

        const result = await pool.query(query, [userId]);

        res.json({ projects: result.rows });
    } catch (error) {
        console.error('Get user projects error:', error);
        res.status(500).json({ error: 'Failed to get projects' });
    }
});

// ==================== FOLLOW SYSTEM ====================

// Follow user
app.post('/api/users/:username/follow', authenticateToken, async (req, res) => {
    try {
        const { username } = req.params;

        const user = await pool.query(
            `SELECT id FROM users WHERE username = $1`,
            [username.toLowerCase()]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.rows[0].id === req.user.id) {
            return res.status(400).json({ error: 'Cannot follow yourself' });
        }

        await pool.query(
            `INSERT INTO user_follows (follower_id, following_id)
             VALUES ($1, $2)
             ON CONFLICT (follower_id, following_id) DO NOTHING`,
            [req.user.id, user.rows[0].id]
        );

        res.json({ message: 'User followed' });
    } catch (error) {
        console.error('Follow user error:', error);
        res.status(500).json({ error: 'Failed to follow user' });
    }
});

// Unfollow user
app.delete('/api/users/:username/follow', authenticateToken, async (req, res) => {
    try {
        const { username } = req.params;

        const user = await pool.query(
            `SELECT id FROM users WHERE username = $1`,
            [username.toLowerCase()]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        await pool.query(
            `DELETE FROM user_follows WHERE follower_id = $1 AND following_id = $2`,
            [req.user.id, user.rows[0].id]
        );

        res.json({ message: 'User unfollowed' });
    } catch (error) {
        console.error('Unfollow user error:', error);
        res.status(500).json({ error: 'Failed to unfollow user' });
    }
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.json({ 
        name: 'Node2D Editor API',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth/*',
            projects: '/api/projects/*',
            users: '/api/users/*',
            explore: '/api/projects/explore'
        }
    });
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ==================== START SERVER ====================

async function start() {
    try {
        await initDatabase();
        
        // Create upload directory
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

start();

module.exports = app;
