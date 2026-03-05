// server.js
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("./models/User");
const Note = require("./models/Note");

const app = express();

// --- CORS setup ---
const corsOptions = {
  origin: "http://localhost:5173",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// --- MongoDB connection ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB error:", err));

const PORT = process.env.PORT || 5000;

// =========================
// AUTH ROUTES
// =========================

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "Email already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash });

    res.json({ message: "User registered", userId: user._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    user.lastLogin = new Date();
    await user.save();

    res.cookie("token", token, { httpOnly: true });
    res.json({ message: "Login successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

// =========================
// AUTH MIDDLEWARE
// =========================
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token || req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// =========================
// NOTES ROUTES
// =========================

// CREATE NOTE
app.post("/api/notes", authMiddleware, async (req, res) => {
  try {
    const { title, content } = req.body;
    const note = await Note.create({
      title,
      content,
      ownerId: req.user.id,
      collaborators: [] // start empty
    });
    res.json(note);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET MY NOTES
app.get("/api/notes", authMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({ ownerId: req.user.id });
    res.json(notes);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ADD COLLABORATOR
app.post("/api/notes/:id/collaborators", authMiddleware, async (req, res) => {
  try {
    const { userId, permission } = req.body;
    const note = await Note.findById(req.params.id);
    if (!note) return res.status(404).json({ error: "Note not found" });

    if (note.ownerId.toString() !== req.user.id) 
      return res.status(403).json({ error: "Not allowed" });

    // Check if already collaborator
    const exists = note.collaborators.some(c => c.userId.toString() === userId);
    if (exists) return res.status(400).json({ error: "User already added" });

    note.collaborators.push({
      userId,
      permission: permission || "view",
      addedBy: req.user.id
    });

    await note.save();
    await note.populate("collaborators.userId", "name username");
    await note.populate("collaborators.addedBy", "name username");

    res.json(note);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// UPDATE NOTE
app.put("/api/notes/:id", authMiddleware, async (req, res) => {
  try {
    const { title, content } = req.body;
    const note = await Note.findById(req.params.id);
    if (!note) return res.status(404).json({ error: "Note not found" });

    // Only owner or collaborators with edit permission
    const collab = note.collaborators.find(c => c.userId.toString() === req.user.id);
    const canEdit = note.ownerId.toString() === req.user.id || (collab && collab.permission === "edit");
    if (!canEdit) return res.status(403).json({ error: "Not allowed to edit" });

    note.title = title || note.title;
    note.content = content || note.content;

    await note.save();
    res.json(note);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE NOTE
app.delete("/api/notes/:id", authMiddleware, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note) return res.status(404).json({ error: "Note not found" });

    if (note.ownerId.toString() !== req.user.id) 
      return res.status(403).json({ error: "Not allowed to delete this note" });

    await Note.findByIdAndDelete(req.params.id);
    res.json({ message: "Note deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET NOTES SHARED WITH ME
app.get("/api/notes/shared", authMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({ "collaborators.userId": req.user.id })
      .populate("ownerId", "name username")
      .populate("collaborators.userId", "name username")
      .populate("collaborators.addedBy", "name username");

    const sharedNotes = notes.map(note => {
      const collab = note.collaborators.find(c => c.userId._id.toString() === req.user.id);
      return {
        _id: note._id,
        title: note.title,
        content: note.content,
        owner: note.ownerId,
        permission: collab.permission,
        sharedBy: collab.addedBy
      };
    });

    res.json(sharedNotes);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET ALL USERS (except yourself)
app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.id } }).select("_id name email");
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET CURRENT USER INFO
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("name email");
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// SEARCH NOTES
app.get("/api/notes/search", authMiddleware, async (req, res) => {
  const { q } = req.query;
  if (!q || q.trim() === "") return res.status(400).json({ error: "Query is required" });

  try {
    const indexes = await Note.collection.indexes();
    const hasTextIndex = indexes.some(idx => Object.values(idx.key).includes("text"));

    if (!hasTextIndex) {
      console.warn("Text index missing. Creating one now.");
      await Note.collection.createIndex({ title: "text", content: "text" });
    }

    const notes = await Note.find(
      { ownerId: req.user.id, $text: { $search: q } },
      { score: { $meta: "textScore" } }
    ).sort({ score: { $meta: "textScore" } });

    res.json(notes);
  } catch (err) {
    console.error("Search failed:", err);
    res.status(500).json({ error: "Search failed" });
  }
});

// =========================
// START SERVER
// =========================
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));