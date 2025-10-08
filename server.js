require('dotenv').config(); // Load environment variables from .env
const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 4000;

// --- Admin password hash (generate once and store in .env) ---
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH; 
// Example hash: $2b$10$abcd... (generate with bcrypt)

// --- Database Setup ---
const db = new sqlite3.Database("./db/store.db", (err) => {
  if (err) {
    console.error("Database error:", err.message);
  } else {
    console.log("✅ Connected to database.");

    // Ensure table exists
    db.run(
      `CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price REAL,
        stock INTEGER,
        image TEXT
      )`,
      (err) => {
        if (err) {
          console.error("Error creating products table:", err);
        } else {
          // Check if "category" column exists
          db.all("PRAGMA table_info(products)", (err, columns) => {
            if (err) {
              console.error("Error checking columns:", err);
              return;
            }

            const hasCategory = columns.some(col => col.name === "category");

            if (!hasCategory) {
              db.run("ALTER TABLE products ADD COLUMN category TEXT DEFAULT ''", (err) => {
                if (err) {
                  console.error("Error adding category column:", err);
                } else {
                  console.log("✅ Added 'category' column to products table.");
                }
              });
            }
          });

          // After ensuring category exists, also ensure featured column
          db.all("PRAGMA table_info(products)", (err, columns) => {
            if (err) {
              console.error("Error checking columns:", err);
              return;
            }

            const hasFeatured = columns.some(col => col.name === "featured");

            if (!hasFeatured) {
              db.run("ALTER TABLE products ADD COLUMN featured INTEGER DEFAULT 0", (err) => {
                if (err) {
                  console.error("Error adding featured column:", err);
                } else {
                  console.log("✅ Added 'featured' column to products table.");
                }
              });
            }
          });
        }
      }
    );
  }
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
app.get("/catalog", (req, res) => {
  // Get recent items (limit 7)
  db.all("SELECT * FROM products ORDER BY id DESC LIMIT 7", (err, recentItems) => {
    if (err) {
      console.error("DB error (recent):", err.message);
      return res.status(500).send("Database error!");
    }

    // Get featured items
    db.all("SELECT * FROM products WHERE featured = 1", (err2, featuredItems) => {
      if (err2) {
        console.error("DB error (featured):", err2.message);
        return res.status(500).send("Database error!");
      }

      res.render("catalog", { recentItems, featuredItems });
    });
  });
});

// Contact page placeholder
app.get("/contact", (req, res) => {
  res.render("contact"); // create contact.ejs if needed
});

app.get("/search", (req, res) => {
  const query = (req.query.query || "").trim().substring(0, 100);
  const category = (req.query.category || "").trim();

  // Get all distinct categories for the dropdown
  db.all(
    "SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ''",
    (err, categories) => {
      if (err) {
        console.error("DB error (categories):", err);
        return res.status(500).send("Database error!");
      }

      let sql = "SELECT * FROM products WHERE LOWER(name) LIKE LOWER(?)";
      const params = [`%${query}%`];

      if (category) {
        sql += " AND LOWER(category) = LOWER(?)";
        params.push(category);
      }

      db.all(sql, params, (err, rows) => {
        if (err) {
          console.error("DB error (search):", err);
          return res.status(500).send("Database error!");
        }

        res.render("search", { 
          products: rows, 
          query, 
          category, 
          categories 
        });
      });
    }
  );
});

// --- Admin Routes ---

// Admin Login Page
app.get("/admin-login", (req, res) => {
  res.render("admin-login", { error: null });
});

// Admin Login POST
app.post("/admin-login", (req, res) => {
  const { password } = req.body;
  if (!password) return res.render("admin-login", { error: "Enter password" });

  bcrypt.compare(password, ADMIN_PASSWORD_HASH, (err, result) => {
    if (err) {
      console.error("Bcrypt error:", err);
      return res.status(500).send("Server error");
    }
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
app.post("/admin/add", checkAdmin, upload.single("imageFile"), (req, res) => {
  const { name, price, stock, imageUrl, category, featured } = req.body;
  const cleanCategory = category ? category.trim() : "";
  const isFeatured = featured === "1" ? 1 : 0;

  let imagePath = "";
  if (req.file) imagePath = "/uploads/" + req.file.filename;
  else if (imageUrl && imageUrl.trim() !== "") imagePath = imageUrl.trim();

  db.run(
    "INSERT INTO products (name, price, stock, image, category, featured) VALUES (?, ?, ?, ?, ?, ?)",
    [name, price, stock, imagePath, cleanCategory || "", isFeatured],
    (err) => {
      if (err) {
        console.error("DB error on add:", err.message);
        return res.status(500).send("Database error!");
      }
      res.redirect("/admin");
    }
  );
});

// Toggle Stock
app.post("/admin/toggle-stock/:id", checkAdmin, (req, res) => {
  const id = req.params.id;

  db.get("SELECT stock FROM products WHERE id = ?", [id], (err, row) => {
    if (err || !row) {
      console.error("Error fetching product:", err?.message || "Not found");
      return res.status(500).send("Database error!");
    }

    const newStock = row.stock > 0 ? 0 : 10; // 0 if in stock, 10 (default) if out
    db.run("UPDATE products SET stock = ? WHERE id = ?", [newStock, id], (err2) => {
      if (err2) {
        console.error("Error updating stock:", err2.message);
        return res.status(500).send("Database error!");
      }
      res.redirect("/admin");
    });
  });
});

// Delete Product (protected)
app.post("/admin/delete/:id", checkAdmin, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM products WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).send("Database error!");
    res.redirect("/admin");
  });
});

// Toggle Featured Selection
app.post("/admin/toggle-featured/:id", checkAdmin, (req, res) => {
  const id = req.params.id;

  db.get("SELECT featured FROM products WHERE id = ?", [id], (err, row) => {
    if (err) {
      console.error("DB error (toggle featured):", err.message);
      return res.status(500).send("Database error!");
    }

    const newStatus = row.featured ? 0 : 1;

    db.run("UPDATE products SET featured = ? WHERE id = ?", [newStatus, id], (err2) => {
      if (err2) {
        console.error("DB error (update featured):", err2.message);
        return res.status(500).send("Database error!");
      }
      res.redirect("/admin");
    });
  });
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


