const bcrypt = require('bcryptjs');
const { db, User, Resident, IncidentReport } = require('./setup');

async function seedDatabase() {
    try {
        // Force sync to reset database
        await db.sync({ force: true });
        console.log('Database reset successfully.');

        // Create sample users (RAs and RDs)
        const hashedPassword = await bcrypt.hash('password123', 10);

        const users = await User.bulkCreate([
            { 
                name: 'Marlee Heiken', 
                email: 'marlee@example.com', 
                role: 'RA', 
                passwordHash: hashedPassword 
            },
            { 
                name: 'Jonathan Kurtz', 
                email: 'jonathan@example.com', 
                role: 'RD', 
                passwordHash: hashedPassword 
            }
        ]);

        // Create sample residents
        const residents = await Resident.bulkCreate([
            { 
                name: 'Student One', 
                roomNumber: '223', 
                building: 'Womack', 
                classYear: 2026, 
                assignedRAId: users[0].id },
            { 
                name: 'Student Two', 
                roomNumber: '957-3', 
                building: 'Works Village', 
                classYear: 2025, 
                assignedRAId: users[0].id 
            },
            { 
                name: 'Student Three', 
                roomNumber: '315', 
                building: 'BG', 
                classYear: 2026, 
                assignedRAId: users[0].id 
            }
        ]);

        // Create sample incident reports
        await IncidentReport.bulkCreate([
            {
                incidentType: 'Noise Complaint',
                peopleInvolved: 'Student One',
                dateTime: new Date(),
                description: 'Loud music after 11 PM',
                location: 'Works Village 975-10',
                reportedById: users[0].id,
                residentId: residents[0].id
            },
            {
                incidentType: 'Maintenance Issue',
                peopleInvolved: 'Student Two',
                dateTime: new Date(),
                description: 'Leaky faucet in room',
                location: 'Womack 315',
                reportedById: users[0].id,
                residentId: residents[1].id
            },
            {
                incidentType: '90 degree door policy',
                peopleInvolved: 'Student Three, Student 4',
                dateTime: new Date(),
                description: 'Door closed when person of oposite sex in room',
                location: 'BG 217',
                reportedById: users[1].id,
                residentId: residents[2].id
            }
        ]);

        console.log('Database seeded successfully!');
        console.log('Sample users created:');
        users.forEach(u => console.log(`- ${u.email} / password123`));
        console.log('Sample residents created:', residents.length);
        console.log('Sample incident reports created:', await IncidentReport.count());

    } catch (error) {
        console.error('Error seeding database:', error);
    } finally {
        await db.close();
    }
}

seedDatabase();
