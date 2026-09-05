import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import { verifyJWT, verifyRole } from "./middleware/verifyJWT.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors({ origin: process.env.CLIENT_URL || "*", credentials: true }));
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

async function run() {
  const db = client.db("legaleaseDB");
  const usersCollection = db.collection("users");
  const lawyersCollection = db.collection("lawyers");
  const hiringsCollection = db.collection("hirings");
  const commentsCollection = db.collection("comments");
  const transactionsCollection = db.collection("transactions");

  const requireRole = (...roles) => verifyRole(usersCollection, ...roles);

  // ---- Auth bridge ----
  app.post("/jwt", async (req, res) => {
    const { email, name } = req.body;
    if (!email) return res.status(400).send({ message: "Email is required" });

    let user = await usersCollection.findOne({ email });
    if (!user) {
      user = { email, name, role: "user", createdAt: new Date() };
      await usersCollection.insertOne(user);
    }

    const token = jwt.sign({ email, name, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.send({ token, role: user.role });
  });

  // ---- Users ----
  app.get("/users/role", verifyJWT, async (req, res) => {
    let user = await usersCollection.findOne({ email: req.decoded.email });
    if (!user) {
      user = { email: req.decoded.email, name: req.decoded.name, role: "user", createdAt: new Date() };
      await usersCollection.insertOne(user);
    }
    res.send({ role: user.role });
  });

  app.patch("/users/set-role", verifyJWT, async (req, res) => {
    const { role } = req.body; // called once right after registration to pick user/lawyer
    if (!["user", "lawyer"].includes(role)) return res.status(400).send({ message: "Invalid role" });
    await usersCollection.updateOne({ email: req.decoded.email }, { $set: { role } });
    res.send({ role });
  });

  app.patch("/users/profile", verifyJWT, async (req, res) => {
    const { name, photo } = req.body;
    const result = await usersCollection.updateOne(
      { email: req.decoded.email },
      { $set: { name, photo } }
    );
    res.send(result);
  });

  app.get("/users", verifyJWT, requireRole("admin"), async (req, res) => {
    const result = await usersCollection.find().toArray();
    res.send(result);
  });

  app.patch("/users/:id/role", verifyJWT, requireRole("admin"), async (req, res) => {
    const { role } = req.body;
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role } }
    );
    res.send(result);
  });

  app.delete("/users/:id", verifyJWT, requireRole("admin"), async (req, res) => {
    const result = await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  });

  // ---- Lawyers (public listing/details, lawyer-owned CRUD) ----
  app.get("/lawyers/featured", async (req, res) => {
    const result = await lawyersCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
    res.send(result);
  });

  app.get("/lawyers/top", async (req, res) => {
    const result = await lawyersCollection.find().sort({ hireCount: -1 }).limit(3).toArray();
    res.send(result);
  });

  app.get("/lawyers", async (req, res) => {
    const { search, specialization, minFee, maxFee, available, page = 1, limit = 9 } = req.query;
    const query = {};
    if (search) query.name = { $regex: search, $options: "i" };
    if (specialization) query.specialization = specialization;
    if (minFee || maxFee) {
      query.hourlyFee = {};
      if (minFee) query.hourlyFee.$gte = Number(minFee);
      if (maxFee) query.hourlyFee.$lte = Number(maxFee);
    }
    if (available === "true") query.status = { $ne: "busy" };

    const skip = (Number(page) - 1) * Number(limit);
    const [items, total] = await Promise.all([
      lawyersCollection.find(query).skip(skip).limit(Number(limit)).toArray(),
      lawyersCollection.countDocuments(query),
    ]);
    res.send({ items, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
  });

  app.get("/lawyers/:id", async (req, res) => {
    const result = await lawyersCollection.findOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  });

  app.get("/my-lawyer-profile", verifyJWT, requireRole("lawyer"), async (req, res) => {
    const result = await lawyersCollection.find({ ownerEmail: req.decoded.email }).toArray();
    res.send(result);
  });

  app.post("/lawyers", verifyJWT, requireRole("lawyer"), async (req, res) => {
    const lawyer = {
      ...req.body,
      hourlyFee: Number(req.body.hourlyFee),
      ownerEmail: req.decoded.email,
      hireCount: 0,
      status: "available",
      createdAt: new Date(),
    };
    const result = await lawyersCollection.insertOne(lawyer);
    res.send(result);
  });

  app.patch("/lawyers/:id", verifyJWT, requireRole("lawyer"), async (req, res) => {
    const lawyer = await lawyersCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!lawyer) return res.status(404).send({ message: "Lawyer not found" });
    if (lawyer.ownerEmail !== req.decoded.email) return res.status(403).send({ message: "Forbidden access" });
    const updateDoc = { $set: { ...req.body } };
    delete updateDoc.$set._id;
    const result = await lawyersCollection.updateOne({ _id: new ObjectId(req.params.id) }, updateDoc);
    res.send(result);
  });

  app.delete("/lawyers/:id", verifyJWT, requireRole("lawyer"), async (req, res) => {
    const lawyer = await lawyersCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!lawyer) return res.status(404).send({ message: "Lawyer not found" });
    if (lawyer.ownerEmail !== req.decoded.email) return res.status(403).send({ message: "Forbidden access" });
    const result = await lawyersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  });

  // ---- Hirings ----
  app.post("/hirings", verifyJWT, async (req, res) => {
    const { lawyerId } = req.body;
    const lawyer = await lawyersCollection.findOne({ _id: new ObjectId(lawyerId) });
    if (!lawyer) return res.status(404).send({ message: "Lawyer not found" });

    const hiring = {
      lawyerId,
      lawyerName: lawyer.name,
      lawyerEmail: lawyer.ownerEmail,
      hourlyFee: lawyer.hourlyFee,
      clientEmail: req.decoded.email,
      clientName: req.decoded.name,
      status: "pending",
      paid: false,
      createdAt: new Date(),
    };
    const result = await hiringsCollection.insertOne(hiring);
    res.send(result);
  });

  app.get("/my-hirings", verifyJWT, async (req, res) => {
    const result = await hiringsCollection.find({ clientEmail: req.decoded.email }).sort({ createdAt: -1 }).toArray();
    res.send(result);
  });

  app.get("/lawyer-hirings", verifyJWT, requireRole("lawyer"), async (req, res) => {
    const result = await hiringsCollection.find({ lawyerEmail: req.decoded.email }).sort({ createdAt: -1 }).toArray();
    res.send(result);
  });

  app.patch("/hirings/:id/status", verifyJWT, requireRole("lawyer"), async (req, res) => {
    const { status } = req.body; // "accepted" | "rejected"
    const hiring = await hiringsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!hiring) return res.status(404).send({ message: "Hiring request not found" });
    if (hiring.lawyerEmail !== req.decoded.email) return res.status(403).send({ message: "Forbidden access" });

    await hiringsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { status } });
    if (status === "accepted") {
      await lawyersCollection.updateOne({ _id: new ObjectId(hiring.lawyerId) }, { $inc: { hireCount: 1 } });
    }
    res.send({ success: true });
  });

  