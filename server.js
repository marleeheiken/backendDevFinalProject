const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { db, User, Resident, IncidentReport } = require('./database/setup');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// JWT Authentication Middleware
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.substring(7);

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired. Please log in again.' });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token. Please log in again.' });
        } else {
            return res.status(401).json({ error: 'Token verification failed.' });
        }
    }
}

function requireRole(requiredRoles) {
    const rolesArray = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

    return (req, res, next) => {
        const userRole = req.user.role; // req.user set by requireAuth

        if (rolesArray.includes(userRole)) {
            // User has one of the required roles, proceed
            next();
        } else {
            // User role is not authorized
            return res.status(403).json({ error: 'Forbidden. You do not have the necessary permissions for this resource.' });
        }
    };
}

const cors = require('cors');
app.use(cors());

// Test database connection
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Database connection established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}
testConnection();

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        message: 'Residence Life API is running',
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString()
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to Residence Life API',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            register: 'POST /api/register',
            login: 'POST /api/login',
            users: 'GET /api/users (requires auth)',
            residents: 'GET /api/residents (requires auth)',
            incidents: 'GET /api/incidents (requires auth)',
        }
    });
});

// ---------------------------
// AUTHENTICATION ROUTES
// ---------------------------

// POST /api/register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, role, password } = req.body;

        if (!name || !email || !role || !password) {
            return res.status(400).json({ error: 'Name, email, role, and password are required' });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({ name, email, role, passwordHash: hashedPassword });

        res.status(201).json({
            message: 'User registered successfully',
            user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );

        res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// ---------------------------
// USER, RESIDENT, INCIDENT ROUTES
// ---------------------------

// GET /api/users
app.get('/api/users', requireAuth, requireRole('RD'), async (req, res) => {
    try {
        const users = await User.findAll();
        res.json({ total: users.length, users });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});


// GET /api/users/:id
app.get('/api/users/:id', requireAuth, requireRole('RD'), async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id, {
            attributes: { exclude: ['passwordHash'] } // Never send password hash
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// GET /api/residents
app.get('/api/residents', requireAuth, requireRole(['RA', 'RD']), async (req, res) => {
    try {
        const userId = req.user.id;
        const userRole = req.user.role;
        let whereClause = {};

        // If the user is an RA, scope the results to their assigned residents
        if (userRole === 'RA') {
            whereClause = {
                assignedRAId: userId // Filter by the RA's ID
            };
        }
        
        // If the user is an RD, the whereClause remains empty, fetching all residents.
        const residents = await Resident.findAll({ 
            where: whereClause,
            include: { model: User, as: 'RA', attributes: ['id', 'name', 'email'] } 
        });
        
        res.json({ total: residents.length, residents });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch residents' });
    }
});

// GET /api/residents/:id
app.get('/api/residents/:id', requireAuth, requireRole('RA','RD'), async (req, res) => {
    try {
        const user = await Resident.findByPk(req.params.id, {
            attributes: { exclude: ['passwordHash'] } // Never send password hash
        });

        if (!user) {
            return res.status(404).json({ error: 'Resident not found' });
        }

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch resident' });
    }
});

// GET /api/incidents
app.get('/api/incidents', requireAuth, requireRole(['RA', 'RD']), async (req, res) => {
    try {
        const userId = req.user.id;
        const userRole = req.user.role;
        let whereClause = {};

        // If the user is an RA, scope the results to reports they made
        if (userRole === 'RA') {
            whereClause = {
                reportedById: userId // Filter by the RA's ID
            };
        }

        // If the user is an RD, the whereClause remains empty, fetching all reports.

        const incidents = await IncidentReport.findAll({ 
            where: whereClause,
            include: ['reporter', 'resident'] 
        });
        
        res.json({ total: incidents.length, incidents });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch incidents' });
    }
});

// GET /api/incidents/:id 
app.get('/api/incidents/:id', requireAuth, requireRole(['RA', 'RD']), async (req, res) => {
    try {
        const incidentId = req.params.id;
        const userRole = req.user.role;
        const userId = req.user.id;
        let whereClause = { id: incidentId }; // Start by filtering for the requested ID

        // **Access Control Logic**
        // If the user is an RA, they can ONLY see reports they created.
        if (userRole === 'RA') {
            whereClause.reportedById = userId; // Add the filter: reportedById must match the logged-in user's ID
        }
        
        // If the user is an RD, the whereClause remains { id: incidentId }, 
        // allowing them to fetch any report by ID.

        const incident = await IncidentReport.findOne({ 
            where: whereClause,
            include: ['reporter', 'resident'] 
        });

        // If the incident is null, it means either:
        // 1. The ID doesn't exist (404)
        // 2. The ID exists, but the RA didn't create it (404 - unauthorized access attempt)
        if (!incident) {
            // Returning a 404 is best practice here, as it doesn't leak information 
            // that a record with that ID exists but is restricted.
            return res.status(404).json({ error: 'Incident report not found or access denied.' });
        }

        res.json(incident);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch incident report' });
    }
});

// POST /api/incidents - CREATE a new Incident Report
app.post('/api/incidents', requireAuth, requireRole(['RA', 'RD']), async (req, res) => {
    try {
        const { incidentType, peopleInvolved, description, location, residentId } = req.body;
        
        // 1. Basic Validation: Check for required fields
        if (!incidentType || !peopleInvolved || !description || !location || !residentId) {
            return res.status(400).json({ error: 'All fields (incidentType, peopleInvolved, description, location, residentId) are required.' });
        }

        // 2. Data Validation: Ensure residentId is valid and exists
        const resident = await Resident.findByPk(residentId);
        if (!resident) {
            return res.status(400).json({ error: 'Invalid residentId. Resident not found.' });
        }

        // 3. Data Assignment: Use the logged-in user's ID and current timestamp
        const newIncident = await IncidentReport.create({
            incidentType,
            peopleInvolved,
            dateTime: new Date(), // Set the current time/date
            description,
            location,
            residentId: residentId,
            reportedById: req.user.id // Crucial: Automatically assign the reporter to the logged-in user
        });

        // 4. Success Response: Fetch the full incident object with associations for a rich response
        const incidentWithDetails = await IncidentReport.findByPk(newIncident.id, {
            include: ['reporter', 'resident']
        });

        res.status(201).json({ 
            message: 'Incident report created successfully.',
            incident: incidentWithDetails 
        });

    } catch (err) {
        // Handle Sequelize/Database errors
        console.error('Error creating incident report:', err);
        res.status(500).json({ error: 'Failed to create incident report' });
    }
});

// PUT /api/incidents/:id - UPDATE an existing Incident Report
app.put('/api/incidents/:id', requireAuth, requireRole(['RA', 'RD']), async (req, res) => {
    try {
        const incidentId = req.params.id;
        const { incidentType, peopleInvolved, description, location, residentId } = req.body;
        const userRole = req.user.role;
        const userId = req.user.id;
        
        // 1. Define Access/Filtering Conditions
        let whereClause = { id: incidentId }; 

        // RAs can only update reports they created (reportedById must match userId)
        if (userRole === 'RA') {
            whereClause.reportedById = userId; 
        } 
        // RDs have no additional filter, allowing them to find any incident by ID.

        // 2. Find the incident, applying the access filter
        const incident = await IncidentReport.findOne({ where: whereClause });

        // If not found, it's either an invalid ID OR the RA doesn't have permission.
        if (!incident) {
            return res.status(404).json({ error: 'Incident report not found or access denied.' });
        }
        
        // 3. Prepare the update data
        // Only include fields that are actually present in the request body
        const updateData = {};
        if (incidentType) updateData.incidentType = incidentType;
        if (peopleInvolved) updateData.peopleInvolved = peopleInvolved;
        if (description) updateData.description = description;
        if (location) updateData.location = location;
        
        // Only allow updating residentId if it's a valid, existing resident (optional validation)
        if (residentId) {
            const resident = await Resident.findByPk(residentId);
            if (!resident) {
                return res.status(400).json({ error: 'Invalid residentId provided for update.' });
            }
            updateData.residentId = residentId;
        }

        // 4. Perform the update
        await incident.update(updateData);

        // 5. Success Response: Fetch the updated incident with associations
        const updatedIncident = await IncidentReport.findByPk(incident.id, {
            include: ['reporter', 'resident']
        });

        res.json({ 
            message: 'Incident report updated successfully.', 
            incident: updatedIncident 
        });

    } catch (err) {
        console.error('Error updating incident report:', err);
        res.status(500).json({ error: 'Failed to update incident report' });
    }
});

// ---------------------------
// Error handling middleware
// ---------------------------
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', message: err.message });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found', message: `${req.method} ${req.path} is not valid` });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});
