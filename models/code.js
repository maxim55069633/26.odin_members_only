const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const CodeSchema = new Schema({
  type: { type: String, required: true },
  value: { type: String, required: true },
});

// Export model
module.exports = mongoose.model("Code", CodeSchema);