const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
require("dotenv").config();

const router = express.Router();

// Register Route
router.post("/register", async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    console.log(req.body);
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res
        .status(400)
        .json({ msg: "Email already exists", status: false, code: 200 });
    }

    user = new User({
      username,
      email,
      password,
      role,
    });

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    res
      .status(201)
      .json({ msg: "User registered successfully", status: true, code: 200 });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Login Route
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if user exists
    let user = await User.findOne({ username });
    if (!user) {
      return res
        .status(400)
        .json({ msg: "Invalid credentials", status: false, code: 200 });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ msg: "Invalid credentials", status: false, code: 200 });
    }

    // Return user data excluding password
    const userData = {
      username: user.username,
      email: user.email,
      role: user.role,
    };

    res.json({
      data: userData,
      msg: "Berhasil Login",
      status: true,
      code: 200,
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

module.exports = router;
