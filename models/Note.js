// models/Note.js
const mongoose = require("mongoose");

const CollaboratorSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  permission: { type: String, enum: ["view", "edit"], default: "view" },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});

const NoteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  collaborators: [CollaboratorSchema],
});

module.exports = mongoose.model("Note", NoteSchema);