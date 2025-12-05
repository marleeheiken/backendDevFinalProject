const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();


// Initialize database connection
const db = new Sequelize({
    dialect: 'sqlite',
    storage: `database/${process.env.DB_NAME}` || 'residency.db',
    logging: false
});

// User Model
const User = db.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    name: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    email: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true 
    },
    role: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    passwordHash: { 
        type: DataTypes.STRING, 
        allowNull: false 
    }
});

// Resident Model
const Resident = db.define('Resident', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    name: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    roomNumber: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    building: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    classYear: { 
        type: DataTypes.INTEGER, 
        allowNull: false 
    }
});

// IncidentReport Model
const IncidentReport = db.define('IncidentReport', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    incidentType: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    peopleInvolved: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    dateTime: { 
        type: DataTypes.DATE, 
        allowNull: false 
    },
    description: { 
        type: DataTypes.TEXT, 
        allowNull: false 
    },
    location: { 
        type: DataTypes.STRING, 
        allowNull: false 
    }
});

// Define Relationships
User.hasMany(Resident, { foreignKey: 'assignedRAId', as: 'residents' });
Resident.belongsTo(User, { foreignKey: 'assignedRAId', as: 'RA' });

User.hasMany(IncidentReport, { foreignKey: 'reportedById', as: 'reports' });
IncidentReport.belongsTo(User, { foreignKey: 'reportedById', as: 'reporter' });

Resident.hasMany(IncidentReport, { foreignKey: 'residentId', as: 'incidents' });
IncidentReport.belongsTo(Resident, { foreignKey: 'residentId', as: 'resident' });

// Initialize database
async function initializeDatabase() {
    try {
        await db.authenticate();
        console.log('Database connection established successfully.');
        
        await db.sync({ force: false }); // use true if you want to reset tables
        console.log('Database synchronized successfully.');
        
    } catch (error) {
        console.error('Unable to connect to database:', error);
    }
}

initializeDatabase();

module.exports = {
    db,
    User,
    Resident,
    IncidentReport
};
