const mongoose = require("mongoose")

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  lastLogin: Date
})

module.exports = mongoose.model("User", userSchema)