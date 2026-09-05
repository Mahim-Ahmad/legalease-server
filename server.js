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

  