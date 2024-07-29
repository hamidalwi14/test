const express = require("express");
const connectDB = require("./config/db");
const bodyParser = require("body-parser");
const auth = require("./routes/auth");
const plants = require("./routes/plants");
const formula = require("./routes/formula");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Connect Database
connectDB();
app.use(express.json());
app.use(cors());
app.options("*", cors());
app.use(
  express.urlencoded({
    enableTypes: ["json", "form"],
    extended: true,
  })
);
app.use(
  express.json({
    extended: true,
  })
);

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// Routes
app.use("/api/auth", auth);
app.use("/api/plants", plants);
app.use("/api/formula", formula);
app.get("/", function (req, res) {
  res.send("Welcome");
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
