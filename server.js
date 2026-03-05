// Load environment variables from a .env file into process.env
require("dotenv").config()

// Import required packages
const express = require("express")          // Web framework for handling routes and middleware
const mongoose = require("mongoose")        // MongoDB ODM for database interactions
const cors = require("cors")                // Middleware to enable Cross-Origin Resource Sharing
const cookieParser = require("cookie-parser") // Middleware to parse cookies from requests
const bcrypt = require("bcrypt")            // For hashing passwords
const jwt = require("jsonwebtoken")         // For creating JSON Web Tokens
const User = require("./models/User")       // Import User model
const Note = require("./models/Note")       // Import Note model

// Initialize Express app
const app = express()

// Middleware setup
app.use(cors())           // Allow requests from other origins
app.use(express.json())   // Parse incoming JSON request bodies
app.use(cookieParser())   // Parse cookies attached to client requests

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB error:", err))
// Define the server port (use environment variable or default to 5000)
const PORT = process.env.PORT || 5000

// =========================
//      AUTH ROUTES
// =========================

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body
    if (!name || !email || !password) return res.status(400).json({ error: "All fields required" })

    const existing = await User.findOne({ email })
    if (existing) return res.status(400).json({ error: "Email already exists" })

    const passwordHash = await bcrypt.hash(password, 10)
    const user = await User.create({ name, email, passwordHash })

    res.json({ message: "User registered", userId: user._id })
  } catch (err) {
    console.error("Registration failed:", err)
    res.status(500).json({ error: "Server error" })
  }
})

// LOGIN
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body
    const user = await User.findOne({ email })
    if (!user) return res.status(400).json({ error: "Invalid credentials" })

    const match = await bcrypt.compare(password, user.passwordHash)
    if (!match) return res.status(400).json({ error: "Invalid credentials" })

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" })
    user.lastLogin = new Date()
    await user.save()

    res.cookie("token", token, { httpOnly: true })
    res.json({ message: "Login successful" })
})

// LOGOUT
app.post("/api/logout", (req, res) => {
    res.clearCookie("token")
    res.json({ message: "Logged out" })
})

// =========================
//      AUTH MIDDLEWARE
// =========================
const authMiddleware = (req, res, next) => {
    const token = req.cookies.token || req.header("Authorization")?.replace("Bearer ", "")
    if (!token) return res.status(401).json({ error: "Unauthorized" })

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        req.user = decoded
        next()
    } catch (err) {
        res.status(401).json({ error: "Invalid token" })
    }
}

// =========================
//      NOTES ROUTES
// =========================

// CREATE NOTE
app.post("/api/notes", authMiddleware, async (req, res) => {
    const { title, content, permission } = req.body
    const note = await Note.create({
        title,
        content,
        ownerId: req.user.id,
        addedBy: req.user.id,
        permission: permission || "edit"
    })
    res.json(note)
})

// GET MY NOTES
app.get("/api/notes", authMiddleware, async (req, res) => {
    const notes = await Note.find({ ownerId: req.user.id })
    res.json(notes)
})

// UPDATE NOTE
app.put("/api/notes/:id", authMiddleware, async (req, res) => {
    const note = await Note.findById(req.params.id)
    if (!note) return res.status(404).json({ error: "Note not found" })
    if (note.ownerId.toString() !== req.user.id && note.permission !== "edit")
        return res.status(403).json({ error: "Not allowed" })

    note.title = req.body.title || note.title
    note.content = req.body.content || note.content
    await note.save()
    res.json(note)
})

// DELETE NOTE
app.delete("/api/notes/:id", authMiddleware, async (req, res) => {
    const note = await Note.findById(req.params.id)
    if (!note) return res.status(404).json({ error: "Note not found" })
    if (note.ownerId.toString() !== req.user.id)
        return res.status(403).json({ error: "Not allowed" })

    await note.deleteOne()
    res.json({ message: "Note deleted" })
})

// ADD COLLABORATOR
app.post("/api/notes/:id/collaborators", authMiddleware, async (req, res) => {
    const { userId, permission } = req.body
    const note = await Note.findById(req.params.id)
    if (!note) return res.status(404).json({ error: "Note not found" })
    if (note.ownerId.toString() !== req.user.id)
        return res.status(403).json({ error: "Not allowed" })

    // Simple implementation: save collaborator and permission
    note.addedBy = userId
    note.permission = permission || "view"
    await note.save()
    res.json(note)
})

// GET NOTES SHARED WITH ME
app.get("/api/notes/shared", authMiddleware, async (req, res) => {
    const notes = await Note.find({ addedBy: req.user.id, permission: "view" })
    res.json(notes)
})

// =========================
//      START SERVER
// =========================
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))