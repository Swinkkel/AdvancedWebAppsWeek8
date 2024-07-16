var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const {body, validationResult } = require("express-validator");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const validateToken = require("../auth/validateToken.js")

router.get('/list', validateToken, (req, res, next) => {
  User.find({}, (err, users) =>{
    if(err) return next(err);
    res.send("User found");
  })

  res.send("Users not found.");
});

router.post('/login', function(req, res, next) {
  res.send('test');
});

router.post('/register', 
  body("email").isLength({min: 3}).trim().escape(),
  body("password").isLength({min: 5}),
  async (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()});
    }

    try {
      const user = await User.findOne({email: req.body.email});
      if (user) {
        return res.status(403).json({ email: "Email already in use."})
      }
      
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(req.body.password, salt);

      await User.create({
        email: req.body.email,
        password: hash
      });
          
      return res.redirect("/users/login");
    }
    catch (err) {
      console.log(err);
      return res.status(500).json({ error: "Server error"});
    }
});

module.exports = router;
