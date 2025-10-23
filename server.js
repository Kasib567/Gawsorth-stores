require('dotenv').config(); // Load environment variables from .env
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcrypt");

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');


const app = express();
app.set('trust proxy', 1); // trust first proxy
const PORT = process.env.PORT || 4000;

// --- Admin password hash (generate once and store in .env) ---
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH; 
// Example hash: $2b$10$abcd... (generate with bcrypt)

// --- Database Setup ---
const { Pool } = require("pg");

// for render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // required for Render
}); 

// For local testing
/*const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
}); */

async function init() {
  try {
    const client = await pool.connect();
    console.log("✅ Connected to PostgreSQL database.");
    client.release();

    // Create the products table
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

    // Create the events table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        date DATE NOT NULL,
        image TEXT
      );
    `);
    console.log("✅ Ensured 'events' table exists.");

    // Start the server AFTER DB is ready
    app.listen(PORT, () => {
      console.log(`🚀 Server running at http://localhost:${PORT}`);
    });

  } catch (err) {
    console.error("❌ Database connection error:", err);
  }
}

// Call the async init function
init();

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure Cloudinary storage for Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  params: {
    folder: "gawsworth_stores", // Change this to your preferred folder name
    allowed_formats: ["jpg", "jpeg", "png", "webp"]
  }
});

// Multer upload middleware using Cloudinary storage
const upload = multer({ storage });

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

// Catalogue (public) with Featured Pagination
app.get("/catalogue", async (req, res) => {
  try {
    // Pagination setup for featured products
    const featuredPage = parseInt(req.query.featuredPage) || 1;
    const featuredLimit = 20; // how many featured items per page
    const featuredOffset = (featuredPage - 1) * featuredLimit;

    // Get recent products (always latest 7)
    const { rows: recentItems } = await pool.query(
      "SELECT * FROM products ORDER BY id DESC LIMIT 7"
    );

    // Count total featured items
    const { rows: featuredCountRows } = await pool.query(
      "SELECT COUNT(*) AS count FROM products WHERE featured = 1"
    );
    const featuredCount = parseInt(featuredCountRows[0].count);
    const totalFeaturedPages = Math.ceil(featuredCount / featuredLimit);

    // Get paginated featured products
    const { rows: featuredItems } = await pool.query(
      "SELECT * FROM products WHERE featured = 1 ORDER BY id DESC LIMIT $1 OFFSET $2",
      [featuredLimit, featuredOffset]
    );

    res.render("catalogue", {
      recentItems,
      featuredItems,
      featuredPage,
      totalFeaturedPages
    });
  } catch (err) {
    console.error("DB error (/catalogue):", err.message);
    res.status(500).send("Database error!");
  }
});

// Contact page placeholder
app.get("/contact", (req, res) => {
  res.render("contact"); // create contact.ejs if needed
});

// Search Section (with pagination)
app.get("/search", async (req, res) => {
  try {
    const query = (req.query.query || "").trim().substring(0, 100);
    const category = (req.query.category || "").trim();
    const page = parseInt(req.query.page) || 1;
    const limit = 20; // show 20 products per page (4 across, 5 down)
    const offset = (page - 1) * limit;

    // Fetch all distinct categories for the dropdown
    const { rows: categories } = await pool.query(`
      SELECT DISTINCT category 
      FROM products 
      WHERE category IS NOT NULL AND category != ''
    `);

    // Build SQL query dynamically
    let sql = "SELECT * FROM products WHERE LOWER(name) LIKE LOWER($1)";
    const params = [`%${query}%`];
    let countSql = "SELECT COUNT(*) FROM products WHERE LOWER(name) LIKE LOWER($1)";

    if (category) {
      sql += " AND LOWER(category) = LOWER($2)";
      countSql += " AND LOWER(category) = LOWER($2)";
      params.push(category);
    }

    sql += " ORDER BY id DESC LIMIT $"+(params.length+1)+" OFFSET $"+(params.length+2);
    const paginatedParams = [...params, limit, offset];

    // Fetch products and total count
    const { rows: products } = await pool.query(sql, paginatedParams);
    const { rows: countResult } = await pool.query(countSql, params);
    const totalProducts = parseInt(countResult[0].count);
    const totalPages = Math.ceil(totalProducts / limit);

    res.render("search", {
      products,
      query,
      category,
      categories,
      page,
      totalPages
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
      res.redirect("/admin-dashboard");
    } else {
      res.render("admin-login", { error: "Incorrect password!" });
    }
  });
});

// Admin Dashboard Page
app.get("/admin-dashboard", checkAdmin, (req, res) => {
  res.render("admin-dashboard");
});

// Admin Panel (with search, filter & pagination)
app.get("/admin", checkAdmin, async (req, res) => {
  try {
    const search = (req.query.search || "").trim().toLowerCase();
    const category = (req.query.category || "").trim();
    const page = parseInt(req.query.page) || 1;
    const limit = 20; // 20 products per page (4 across, 5 down)
    const offset = (page - 1) * limit;

    // Build WHERE conditions dynamically
    let conditions = [];
    let params = [];

    if (search) {
      conditions.push(`LOWER(name) LIKE $${params.length + 1}`);
      params.push(`%${search}%`);
    }

    if (category) {
      conditions.push(`LOWER(category) = LOWER($${params.length + 1})`);
      params.push(category);
    }

    // Combine conditions
    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Count total matching products
    const countQuery = `SELECT COUNT(*) AS count FROM products ${whereClause}`;
    const countResult = await pool.query(countQuery, params);
    const totalProducts = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalProducts / limit);

    // Add pagination to params
    const productQuery = `
      SELECT * FROM products
      ${whereClause}
      ORDER BY id DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    params.push(limit, offset);

    const { rows: products } = await pool.query(productQuery, params);
    const { rows: categories } = await pool.query(`
      SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != '' ORDER BY category ASC
    `);

    res.render("admin", {
      products,
      categories,
      search,
      category,
      currentPage: page,
      totalPages
    });
  } catch (err) {
    console.error("DB error (admin):", err.message);
    res.status(500).send("Database error!");
  }
});

// Add Product
app.post("/admin/add", checkAdmin, upload.single("imageFile"), async (req, res) => {
  try {
    const { name, stock, imageUrl, category, featured } = req.body;
    const cleanCategory = category ? category.trim() : "";
    const isFeatured = featured === "1" ? 1 : 0;

    // Use Cloudinary image if uploaded, or fallback to manual URL
    let imagePath = "";
    if (req.file && req.file.path) {
      imagePath = req.file.path; // Cloudinary-hosted image URL
    } else if (imageUrl && imageUrl.trim() !== "") {
      imagePath = imageUrl.trim();
    }

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

// Delete Product (with Cloudinary cleanup)
app.post("/admin/delete/:id", checkAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // Get image URL from DB
    const { rows } = await pool.query("SELECT image FROM products WHERE id = $1", [id]);
    const imageUrl = rows[0]?.image;

    // Delete product from DB
    await pool.query("DELETE FROM products WHERE id = $1", [id]);

    // If image is hosted on Cloudinary, delete it from Cloudinary
    if (imageUrl && imageUrl.includes("res.cloudinary.com")) {
      // Extract public_id from Cloudinary URL
      const parts = imageUrl.split("/");
      const publicIdWithExtension = parts.slice(-1)[0]; // e.g., 'image-12345.jpg'
      const publicId = publicIdWithExtension.split(".")[0]; // remove extension

      // Optional: include your folder path if you used one
      await cloudinary.uploader.destroy(publicId);
      console.log("🧹 Deleted Cloudinary image:", publicId);
    }

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


// --- EVENTS SECTION ---

// Public Events Page
app.get("/events", async (req, res) => {
  try {
    const { rows: events } = await pool.query("SELECT * FROM events ORDER BY date DESC");
    res.render("events", { events });
  } catch (err) {
    console.error("Error fetching events:", err.message);
    res.status(500).send("Database error!");
  }
});

// Admin - Add Event Page
app.get("/admin/events", checkAdmin, async (req, res) => {
  try {
    const { rows: events } = await pool.query("SELECT * FROM events ORDER BY date DESC");
    res.render("admin-events", { events });
  } catch (err) {
    console.error("Error loading admin events:", err.message);
    res.status(500).send("Database error!");
  }
});

// Admin - Add Event POST
app.post("/admin/events/add", checkAdmin, upload.single("imageFile"), async (req, res) => {
  try {
    const { title, description, date } = req.body;
    let imagePath = "";
    if (req.file && req.file.path) {
      imagePath = req.file.path; // Cloudinary-hosted URL
    }

    await pool.query(
      "INSERT INTO events (title, description, date, image) VALUES ($1, $2, $3, $4)",
      [title, description, date, imagePath]
    );

    res.redirect("/admin/events");
  } catch (err) {
    console.error("Error adding event:", err.message);
    res.status(500).send("Database error!");
  }
});

// Admin - Delete Event
app.post("/admin/events/delete/:id", checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("DELETE FROM events WHERE id = $1", [id]);
    res.redirect("/admin/events");
  } catch (err) {
    console.error("Error deleting event:", err.message);
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

// Privacy Policy
app.get("/privacy", (req, res) => {
  res.render("privacy");
});

// Terms of Use
app.get("/terms", (req, res) => {
  res.render("terms");
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something went wrong!");
});



