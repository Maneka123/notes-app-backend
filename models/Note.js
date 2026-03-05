const mongoose = require("mongoose")

const noteSchema = new mongoose.Schema({
  title: String,
  content: String,
  ownerId: String,
  addedBy: String,
  permission: { type: String, default: "edit" }
})

module.exports = mongoose.model("Note", noteSchema)