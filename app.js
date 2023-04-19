require('dotenv').config();

var createError = require('http-errors');
const { body, validationResult } = require("express-validator");

var express = require('express');
var path = require('path');
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");

const User = require("./models/user");
const Message = require("./models/message");
const Code = require("./models/code");

const async = require("async");

const mongoDb = process.env.MONGODB_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

var cookieParser = require('cookie-parser');
var logger = require('morgan');

const bcrypt = require("bcryptjs");
var app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

// three functions to authenticate users 
passport.use(
  new LocalStrategy(async(username, password, done) => {

      try {
        const user = await User.findOne({ email: username });
        if (!user) {
          return done(null, false, { message: "Incorrect email" });
        };
        // if (user.password !== password) {
        //   return done(null, false, { message: "Incorrect password" });
        // };
        bcrypt.compare(password, user.password, (err, res) => {
          if (res) {
            console.log("successfully logged in.");
            

            // passwords match! log user in
            return done(null, user);
          } else {
            // passwords do not match!
            return done(null, false, { message: "Incorrect password" })
          }
        });
      } catch(err) {
        return done(err);
      };
    
  })
);

//   Functions two and three: Sessions and serialization 
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch(err) {
    done(err);
  };
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => res.render("index"));

app.get("/user/:id/", (req, res) => {
  res.render("user", { user: req.user });
});

app.get("/user/:id/message", async (req, res) => {
  
  const current_user = await User.findById(req.params.id).exec();
  try {
    const allMessages = await Message.find().populate("user").exec();
    res.render("message-board", { user: current_user, messages: allMessages });
    // res.redirect(`/user/${req.params.id}/`);
  } catch (err) {
    next(err);
  }
});

app.post("/user/:id/message", [
  body("message", "Message required").trim().isLength({ min: 1 }).escape(),
 // Process request after validation and sanitization.
  async (req, res, next) => {

  // Extract the validation errors from a request.
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(errors.array());
  }

  const current_user = await  User.findById(req.params.id).exec();

  const message = new Message({
    text: req.body.message,
    user: current_user,
    timestamp: new Date(),
  });

  try {
    await message.save();

    const allMessages = await Message.find().exec();
    res.render("message-board", { user: current_user, messages: allMessages });
    // res.redirect(`/user/${req.params.id}/`);
  } catch (err) {
    next(err);
  }
 },
] );

app.get("/user/:id/member", (req, res)=>{
  res.render("member", { user: res.locals.currentUser});
});

app.post("/user/:id/member", [
  body("member_code", "Member code required").trim().isLength({ min: 1 }).escape(),
 // Process request after validation and sanitization.
  async (req, res, next) => {

  // Extract the validation errors from a request.
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(errors.array());
  }

  const right_member_code = (await Code.find({type: "member"}).exec())[0].value;
  const current_user = await User.findById(req.params.id).exec();

  console.log("Outside the if statement");
  console.log(req.body.member_code );
  console.log(right_member_code);
  console.log(req.body.member_code == right_member_code);


  if(req.body.member_code == right_member_code ) {

    console.log("Inside the if statement");
    console.log(right_member_code);
    
    const modified_user = new User({
      first_name: current_user.first_name,
      family_name: current_user.family_name,
      email: current_user.email,
      password: current_user.password,
      membership : true,
      admin : current_user.admin,
      _id: current_user.id, // This is required, or a new ID will be assigned!
    });

    
    try {
      await User.findByIdAndUpdate(current_user.id, modified_user, {});  
      res.render("member", { user: current_user});
      // res.redirect(`/user/${req.params.id}/`);
    } catch (err) {
      next(err);
    }
  } else {
    res.render("member");
  }
  
 },
] )

app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", async (req, res, next) => {
  bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
    // if err, do something
    if (err) 
      return next(err);
    // otherwise, store hashedPassword in DB
    else {
      try {
        const user = new User({
          first_name: req.body.first_name,
          family_name: req.body.family_name,
          // email: req.body.email,
          email: req.body.username,
          password: hashedPassword,
          membership: false,
          admin: false,
        });
        const result = await user.save();
        res.redirect(`/user/${user.id}/`);
  
      } catch(err) {
        return next(err);
      };
    }
  });
  });

app.get("/log-in", (req, res) => res.render("log-in-form"));

app.post(
  "/log-in",
  passport.authenticate("local", {
    // successRedirect: `/`,
    failureRedirect: "/log-in"
  }),
  function (req, res) {

    res.cookie('userid', req.user.id);
    res.redirect(`/user/${req.user.id}`);
  }
);

app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.clearCookie("userid");
    res.redirect("/");
  });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
