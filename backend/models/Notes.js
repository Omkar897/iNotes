const mongoose = require("mongoose");

const NotesSchema = new Schema({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: Date,
    required: true,
  },
  tag: {
    type: Date,
    default: "General",
  },
  date: {
    type: Date,
    default: Date.now,
  },
});
module.exports = mongoose.model("notes", NotesSchemaSchema);
