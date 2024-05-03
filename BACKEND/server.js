// server.js
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const User = require("./models/User");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/tp", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));

const secret_key = "123456789abcd";

// Authentication route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // Server-side validation
  if (!email) {
    return res.status(400).json({ email: "Email is required" });
  }

  if (!password) {
    return res.status(400).json({ password: "Password is required" });
  }

  try {
    // Find user by email
    const user = await User.findOne({ email });

    if (!user) {
      console.log(`Not found user ${user}`);
      return res.status(404).json({ email: "User not found" });
    }

    if (user.password !== password) {
      return res.status(401).json({ password: "Password not valid" });
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email, role: user.role }, secret_key, {
      expiresIn: "1d",
    });
    res.json({ token, user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Protected route
app.get("/api/dashboard", authenticateToken, (req, res) => {
  res.status(200).json({ message: "protected dashboard data" });
});

// Admin route
app.get("/api/admin", authenticateToken, authenticateAdmin, (req, res) => {
  res.status(200).json({ message: "Protected admin data" });
});

function authenticateToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (bearerHeader) {
    const bearerToken = bearerHeader.split(" ")[1];
    jwt.verify(bearerToken, secret_key, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: "Invalid token" });
      }
      console.log(`decoded token ${decoded}`);
      req.user = decoded;
      next();
    });
  } else {
    res.status(403).json({ message: "Token not provided" });
  }
}

function authenticateAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(401).json({ message: "Unauthorized user" });
  }
  next();
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));