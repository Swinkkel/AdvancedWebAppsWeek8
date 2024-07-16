var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const {body, validationResult } = require("express-validator");
const User = require("../models/User");
const Todo = require("../models/Todo");
const jwt = require("jsonwebtoken");
const validateToken = require("../auth/validateToken.js")

router.get('/private', validateToken, (req, res, next) => {
  res.json({ email: req.user.email });
});

router.post('/todos', validateToken, async (req, res, next) => {
    const { items } = req.body;
    if (!items || !Array.isArray(items) || !items.length) {
      return res.status(400).json({ error: 'Invalid items format' });
    }

    try {
      let todo = await Todo.findOne({ user: req.user.id });
      if (!todo) {
        todo = new Todo({
          user: req.user.id,
          items
        });
      } else {
        todo.items = [...todo.items, ...items];
      }

      await todo.save();
      res.status(201).json(todo);
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  }
);

router.post('/user/login',  async (req, res, next) => {
    try {
      const user = await User.findOne({email: req.body.email});
      if (!user) {
        return res.status(403).json({ error: "Invalid user or password."});
      }

      console.log(user);

      bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
        if(err) throw err;
        if(isMatch) {
          const jwtPayload = {
            email: user.email
          }
          jwt.sign(
            jwtPayload,
            process.env.SECRET,
            {
              expiresIn: 120
            },
            (err, token) => {
              res.json({success: true, token});
            }
          );
        }
      });
    }
    catch (err) {
      console.log(err);
      return res.status(500).json({ error: "Server error"});
    }
});

router.post('/user/register', 
  // Email must be in valid format
  body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
  // Password must be at least 8 characters long, include one lowercase letter, one uppercase letter, one number, and one special character
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[\W_]/).withMessage('Password must contain at least one special character'),  
  async (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()});
    }

    try {
      const user = await User.findOne({email: req.body.email});
      if (user) {
        return res.status(403).json({ email: "Email already in use."});
      }
      
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(req.body.password, salt);

      await User.create({
        email: req.body.email,
        password: hash
      });
        
      return res.json({ message: "Ok"});
      //return res.redirect("/users/login");
    }
    catch (err) {
      console.log(err);
      return res.status(500).json({ error: "Server error"});
    }
});

module.exports = router;
