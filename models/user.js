const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const UserSchema = new Schema({
  first_name: { type: String, required: true, maxLength: 100 },
  family_name: { type: String, required: true, maxLength: 100 },
  // email: { type: String, required: true  },
  email: { type: String, required: true  },
  password: { type: String, required: true },
  membership: {type: Boolean},
  admin: { type: Boolean },
});

UserSchema.virtual("name").get(function () {
  let fullname = "";
  if (this.first_name && this.family_name) {
    fullname = `${this.first_name} ${this.family_name}`;
  }
  if (!this.first_name || !this.family_name) {
    fullname = "";
  }
  return fullname;
});

// Export model
module.exports = mongoose.model("User", UserSchema);