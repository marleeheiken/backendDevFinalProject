const request = require("supertest");

// Mock database with full path from project root
jest.mock(require.resolve("../database/setup"), () => ({
  User: {
    findAll: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    destroy: jest.fn(),
    findByPk: jest.fn(),
  },
  Resident: {
    findAll: jest.fn(),
    create: jest.fn(),
    findByPk: jest.fn(),
    destroy: jest.fn(),
  },
  IncidentReport: {
    findAll: jest.fn(),
    findByPk: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    destroy: jest.fn(),
  },
  db: {
    authenticate: jest.fn().mockResolvedValue(),
    sync: jest.fn().mockResolvedValue(),
    close: jest.fn().mockResolvedValue(),
  },
}));

// Mock JWT
jest.mock("jsonwebtoken", () => ({
  sign: jest.fn(() => "mock-token"),
  verify: jest.fn(() => ({
    id: 1,
    name: "Test User",
    email: "test@test.com",
    role: "RD",
  })),
}));

// Mock bcrypt
jest.mock("bcryptjs", () => ({
  hash: jest.fn(() => Promise.resolve("hashed-password")),
  compare: jest.fn(() => Promise.resolve(true)),
}));

// Mock dotenv
jest.mock("dotenv", () => ({
  config: jest.fn(),
}));

// Mock cors
jest.mock("cors", () => jest.fn(() => (req, res, next) => next()));

const { User, Resident, IncidentReport, db } = require("../database/setup");

// Import the app AFTER all mocks are set up
const app = require("../server");

// ----------------------------
// CLEANUP AFTER TESTS
// ----------------------------
afterAll(async () => {
  await db.close();
});

// ----------------------------
// USERS TESTS
// ----------------------------
describe("User Routes", () => {
  beforeEach(() => jest.clearAllMocks());

  test("GET /api/users returns all users", async () => {
    User.findAll.mockResolvedValue([{ id: 1, name: "Alice" }]);
    const res = await request(app)
      .get("/api/users")
      .set("Authorization", "Bearer mock-token");
    expect(res.status).toBe(200);
    expect(res.body.users.length).toBe(1);
  });

  test("POST /api/register registers a new user", async () => {
    User.findOne.mockResolvedValue(null);
    User.create.mockResolvedValue({
      id: 2,
      name: "Bob",
      email: "bob@test.com",
      role: "RA",
    });

    const res = await request(app).post("/api/register").send({
      name: "Bob",
      email: "bob@test.com",
      role: "RA",
      password: "password123",
    });

    expect(res.status).toBe(201);
    expect(res.body.user.name).toBe("Bob");
  });

  test("DELETE /api/users/:id deletes user", async () => {
    User.destroy.mockResolvedValue(1);
    const res = await request(app)
      .delete("/api/users/2")
      .set("Authorization", "Bearer mock-token");
    expect(res.status).toBe(204);
  });
});

// ----------------------------
// RESIDENTS TESTS
// ----------------------------
describe("Resident Routes", () => {
  beforeEach(() => jest.clearAllMocks());

  test("GET /api/residents returns residents", async () => {
    Resident.findAll.mockResolvedValue([{ id: 1, name: "Res A" }]);
    const res = await request(app)
      .get("/api/residents")
      .set("Authorization", "Bearer mock-token");
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
  });

  test("POST /api/residents creates a resident", async () => {
    User.findOne.mockResolvedValue({ id: 3, role: "RA" });
    Resident.create.mockResolvedValue({ id: 1 });
    Resident.findByPk.mockResolvedValue({ id: 1, name: "New Res" });

    const res = await request(app)
      .post("/api/residents")
      .set("Authorization", "Bearer mock-token")
      .send({
        name: "New Res",
        roomNumber: "101",
        building: "A",
        classYear: "2027",
        assignedRAId: 3,
      });

    expect(res.status).toBe(201);
    expect(res.body.resident.id).toBe(1);
  });

  test("DELETE /api/residents/:id deletes resident", async () => {
    Resident.destroy.mockResolvedValue(1);
    const res = await request(app)
      .delete("/api/residents/1")
      .set("Authorization", "Bearer mock-token");
    expect(res.status).toBe(204);
  });
});

// ----------------------------
// INCIDENT REPORT TESTS
// ----------------------------
describe("Incident Routes", () => {
  beforeEach(() => jest.clearAllMocks());

  test("GET /api/incidents returns incidents", async () => {
    IncidentReport.findAll.mockResolvedValue([
      { id: 1, description: "Broken window" },
    ]);
    const res = await request(app)
      .get("/api/incidents")
      .set("Authorization", "Bearer mock-token");
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
  });

  test("POST /api/incidents creates an incident", async () => {
    Resident.findByPk.mockResolvedValue({ id: 1 });
    IncidentReport.create.mockResolvedValue({ id: 2 });
    IncidentReport.findByPk.mockResolvedValue({
      id: 2,
      description: "Fire alarm",
    });

    const res = await request(app)
      .post("/api/incidents")
      .set("Authorization", "Bearer mock-token")
      .send({
        incidentType: "Fire",
        peopleInvolved: ["John"],
        description: "Fire alarm went off",
        location: "Dorm A",
        residentId: 1,
      });

    expect(res.status).toBe(201);
    expect(res.body.incident.id).toBe(2);
  });

  test("PUT /api/incidents/:id updates an incident", async () => {
    IncidentReport.findOne.mockResolvedValue({
      id: 2,
      update: jest.fn().mockResolvedValue(),
    });
    IncidentReport.findByPk.mockResolvedValue({
      id: 2,
      description: "Updated incident",
    });

    const res = await request(app)
      .put("/api/incidents/2")
      .set("Authorization", "Bearer mock-token")
      .send({
        description: "Updated incident",
      });

    expect(res.status).toBe(200);
    expect(res.body.incident.description).toBe("Updated incident");
  });

  test("DELETE /api/incidents/:id deletes an incident", async () => {
    IncidentReport.destroy.mockResolvedValue(1);
    const res = await request(app)
      .delete("/api/incidents/2")
      .set("Authorization", "Bearer mock-token");
    expect(res.status).toBe(204);
  });
});