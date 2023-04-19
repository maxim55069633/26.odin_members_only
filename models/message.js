const mongoose = require("mongoose");
const { DateTime } = require("luxon");
const Schema = mongoose.Schema;

const MessageSchema = new Schema({
  timestamp: { type: Date, required: true },
  text: { type: String , required: true },
  user: { type: Schema.Types.ObjectId, ref: "User", required: true },
});

MessageSchema.virtual("date_formatted").get(function () {
  return DateTime.fromJSDate(this.timestamp).toFormat('hh:mm:ss -- MMMM dd, yyyy');
});

// Export model
module.exports = mongoose.model("Message", MessageSchema);