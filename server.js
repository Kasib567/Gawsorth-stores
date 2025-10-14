require('dotenv').config(); // Load environment variables from .env
const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
app.set('trust proxy', 1); // trust first proxy
const PORT = process.env.PORT || 4000;

// --- Admin password hash (generate once and store in .env) ---
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH; 
// Example hash: $2b$10$abcd... (generate with bcrypt)

// --- Database Setup ---
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // required for Render
});

pool.connect()
  .then(async client => {
    console.log("✅ Connected to PostgreSQL database.");
    client.release();

    // Create the products table (no price column)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        stock INTEGER DEFAULT 0,
        image TEXT,
        category TEXT DEFAULT '',
        featured INTEGER DEFAULT 0
      );
    `);
    console.log("✅ Ensured 'products' table exists.");
  })
  .catch(err => {
    console.error("❌ Database connection error:", err);
  });



const multer = require("multer");

// Set storage for uploaded images
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/"); // folder to save
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
    const ext = file.originalname.split('.').pop();
    cb(null, file.fieldname + "-" + uniqueSuffix + "." + ext);
  }
});

const upload = multer({ storage: storage });

// --- Middleware ---
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// --- Secure Session Middleware ---
app.use(session({
  secret: process.env.SESSION_SECRET || "replace_with_random_string",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                    // prevents client-side JS from reading cookie
    secure: process.env.NODE_ENV === "production", // only send cookie over HTTPS
    maxAge: 1000 * 60 * 60             // 1 hour
  }
}));

// --- Logging ---
app.use((req, res, next) => {
  console.log(`Request: ${req.method} ${req.url}`);
  next();
});

// --- Helper Middleware ---
function checkAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.redirect("/admin-login");
  next();
}

// --- Routes ---

// Home
app.get("/", (req, res) => {
  res.render("index");
});

// Catalog (public)
app.get("/catalog", async (req, res) => {
  try {
    const { rows: recentItems } = await pool.query("SELECT * FROM products ORDER BY id DESC LIMIT 7");
    const { rows: featuredItems } = await pool.query("SELECT * FROM products WHERE featured = 1");
    res.render("catalog", { recentItems, featuredItems });
  } catch (err) {
    console.error("DB error:", err.message);
    res.status(500).send("Database error!");
  }
});

// Contact page placeholder
app.get("/contact", (req, res) => {
  res.render("contact"); // create contact.ejs if needed
});

// Search Section
app.get("/search", async (req, res) => {
  try {
    const query = (req.query.query || "").trim().substring(0, 100);
    const category = (req.query.category || "").trim();

    // Fetch all distinct categories for the dropdown
    const { rows: categories } = await pool.query(
      "SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ''"
    );

    // Build SQL query dynamically
    let sql = "SELECT * FROM products WHERE LOWER(name) LIKE LOWER($1)";
    const params = [`%${query}%`];

    if (category) {
      sql += " AND LOWER(category) = LOWER($2)";
      params.push(category);
    }

    // Run search
    const { rows: products } = await pool.query(sql, params);

    // Render search results
    res.render("search", {
      products,
      query,
      category,
      categories,
    });

  } catch (err) {
    console.error("DB error (search):", err.message);
    res.status(500).send("Database error!");
  }
});

// --- Admin Routes ---

// Admin Login Page
app.get("/admin-login", (req, res) => {
  res.render("admin-login", { error: null });
});

// Admin Login POST
app.post("/admin-login", (req, res) => {
  const { password } = req.body;
  console.log("Password entered:", password);
  console.log("Admin hash from env:", ADMIN_PASSWORD_HASH);

  if (!password) return res.render("admin-login", { error: "Enter password" });

  bcrypt.compare(password, ADMIN_PASSWORD_HASH, (err, result) => {
    if (err) {
      console.error("Bcrypt error:", err);
      return res.status(500).send("Server error");
    }
    console.log("bcrypt.compare result:", result); // true or false
    if (result) {
      req.session.isAdmin = true;
      res.redirect("/admin");
    } else {
      res.render("admin-login", { error: "Incorrect password!" });
    }
  });
});

// Admin Panel (protected)
app.get("/admin", checkAdmin, (req, res) => {
  db.all("SELECT * FROM products", [], (err, rows) => {
    if (err) return res.status(500).send("Database error!");
    res.render("admin", { products: rows });
  });
});

// Add Product
app.post("/admin/add", checkAdmin, upload.single("imageFile"), async (req, res) => {
  try {
    const { name, stock, imageUrl, category, featured } = req.body;
    const cleanCategory = category ? category.trim() : "";
    const isFeatured = featured === "1" ? 1 : 0;

    let imagePath = "";
    if (req.file) imagePath = "/uploads/" + req.file.filename;
    else if (imageUrl && imageUrl.trim() !== "") imagePath = imageUrl.trim();

    // Insert product into DB
    await pool.query(
      "INSERT INTO products (name, stock, image, category, featured) VALUES ($1, $2, $3, $4, $5)",
      [name, stock, imagePath, cleanCategory || "", isFeatured]
    );

    res.redirect("/admin");
  } catch (err) {
    console.error("DB error on add:", err.message);
    res.status(500).send("Database error!");
  }
});

// Toggle Stock
app.post("/admin/toggle-stock/:id", checkAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    // Get current stock
    const result = await pool.query("SELECT stock FROM products WHERE id = $1", [id]);
    if (result.rows.length === 0) {
      console.error("Product not found for ID:", id);
      return res.status(404).send("Product not found");
    }

    const currentStock = result.rows[0].stock;
    const newStock = currentStock > 0 ? 0 : 10; // toggle 0 ↔ 10

    // Update stock
    await pool.query("UPDATE products SET stock = $1 WHERE id = $2", [newStock, id]);

    res.redirect("/admin");
  } catch (err) {
    console.error("Error toggling stock:", err.message);
    res.status(500).send("Database error!");
  }
});

// Delete Product
app.post("/admin/delete/:id", checkAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM products WHERE id = $1", [id]);
    res.redirect("/admin");
  } catch (err) {
    console.error("Error deleting product:", err.message);
    res.status(500).send("Database error!");
  }
});

// Toggle Featured Selection
app.post("/admin/toggle-featured/:id", checkAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // Get current featured status
    const result = await pool.query("SELECT featured FROM products WHERE id = $1", [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("Product not found");
    }

    const currentStatus = result.rows[0].featured;
    const newStatus = currentStatus ? 0 : 1;

    // Update featured status
    await pool.query("UPDATE products SET featured = $1 WHERE id = $2", [newStatus, id]);

    res.redirect("/admin");
  } catch (err) {
    console.error("DB error (toggle featured):", err.message);
    res.status(500).send("Database error!");
  }
});

// Admin Logout
app.get("/admin-logout", checkAdmin, (req, res) => {
  req.session.destroy(err => {
    if (err) console.error("Logout error:", err);
    res.redirect("/admin-login");
  });
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something went wrong!");
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});


