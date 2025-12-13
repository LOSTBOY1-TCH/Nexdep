const express = require("express")
const mongoose = require("mongoose")
const { GridFSBucket } = require("mongodb")
const multer = require("multer")
const path = require("path")
const crypto = require("crypto")
const session = require("express-session")

const app = express()

const uploadMemory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
})

// Middleware
app.use(express.static(path.join(__dirname, "../public")))
app.use(express.json({ limit: "100mb" }))
app.use(express.urlencoded({ limit: "100mb", extended: true }))

app.use(
  session({
    secret: process.env.SESSION_SECRET || "nexdrop-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: "none",
    },
  }),
)

// MongoDB Connection
let cachedDb = null

async function connectDatabase() {
  if (cachedDb && mongoose.connection.readyState === 1) {
    return cachedDb
  }

  try {
    const MONGODB_URI = process.env.MONGODB_URI

    if (!MONGODB_URI) {
      throw new Error("MONGODB_URI environment variable is not set")
    }

    await mongoose.connect(MONGODB_URI, {
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 60000,
      family: 4,
    })

    cachedDb = mongoose.connection.getClient().db()

    // Initialize admin user
    await initializeAdmin()

    return cachedDb
  } catch (err) {
    console.error("MongoDB connection error:", err)
    throw err
  }
}

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
})

const fileMetadataSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  uploaderId: mongoose.Schema.Types.ObjectId,
  uploaderName: String,
  size: Number,
  mimeType: String,
  uploadDate: { type: Date, default: Date.now },
  downloadCount: { type: Number, default: 0 },
  downloadSlug: { type: String, unique: true },
  visibility: { type: String, default: "public" },
  tags: [String],
  storageType: { type: String, enum: ["gridfs"], default: "gridfs" },
})

const siteStatsSchema = new mongoose.Schema({
  totalViews: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now },
})

const User = mongoose.models.User || mongoose.model("User", userSchema)
const FileMetadata = mongoose.models.FileMetadata || mongoose.model("FileMetadata", fileMetadataSchema)
const SiteStats = mongoose.models.SiteStats || mongoose.model("SiteStats", siteStatsSchema)

const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, message: "Not authenticated" })
  }
  next()
}

async function initializeAdmin() {
  try {
    const adminExists = await User.findOne({ username: "nex" })
    if (!adminExists) {
      const hashedPassword = crypto.createHash("sha256").update("n1n2nanaagye").digest("hex")
      await User.create({
        username: "nex",
        email: "admin@nexdrop.com",
        password: hashedPassword,
        isAdmin: true,
      })
    }
  } catch (err) {
    console.error("Admin initialization error:", err)
  }
}

app.use(async (req, res, next) => {
  try {
    await connectDatabase()
    next()
  } catch (err) {
    console.error("Database connection failed:", err)
    return res.status(503).json({
      success: false,
      error: "Database connection failed. Please check MONGODB_URI environment variable.",
    })
  }
})

// Auth Routes
app.post("/api/signup", async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body
    if (password !== confirmPassword) {
      return res.json({ success: false, message: "Passwords do not match" })
    }
    const exists = await User.findOne({ $or: [{ username }, { email }] })
    if (exists) {
      return res.json({ success: false, message: "Username or email already exists" })
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")
    const user = await User.create({ username, email, password: hashedPassword })

    req.session.userId = user._id
    req.session.username = user.username
    req.session.isAdmin = false

    res.json({ success: true, redirect: "/dashboard" })
  } catch (err) {
    res.json({ success: false, message: err.message })
  }
})

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await User.findOne({ username })
    if (!user) {
      return res.json({ success: false, message: "User not found" })
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")
    if (user.password !== hashedPassword) {
      return res.json({ success: false, message: "Invalid password" })
    }
    if (user.isBanned) {
      return res.json({ success: false, message: "Your account is banned" })
    }

    req.session.userId = user._id
    req.session.username = user.username
    req.session.isAdmin = user.isAdmin

    res.json({ success: true, redirect: "/dashboard" })
  } catch (err) {
    res.json({ success: false, message: err.message })
  }
})

app.get("/api/logout", (req, res) => {
  req.session.destroy()
  res.json({ success: true })
})

app.get("/api/auth/check", (req, res) => {
  if (req.session.userId) {
    res.json({
      authenticated: true,
      username: req.session.username,
      isAdmin: req.session.isAdmin || false,
    })
  } else {
    res.json({ authenticated: false })
  }
})

// File Upload Routes
app.post("/api/upload", uploadMemory.single("file"), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ success: false, message: "Not authenticated" })
    }
    if (!req.file) {
      return res.json({ success: false, message: "No file provided" })
    }

    const downloadSlug = crypto.randomBytes(16).toString("hex")
    const db = cachedDb || mongoose.connection.getClient().db()
    const gridFSBucket = new GridFSBucket(db)

    const fileMetadata = await FileMetadata.create({
      filename: downloadSlug,
      originalName: req.file.originalname,
      uploaderId: req.session.userId,
      uploaderName: req.session.username,
      size: req.file.size,
      mimeType: req.file.mimetype,
      downloadSlug,
      visibility: "public",
      storageType: "gridfs",
    })

    const uploadStream = gridFSBucket.openUploadStream(downloadSlug, {
      metadata: { originalName: req.file.originalname },
    })

    uploadStream.end(req.file.buffer)

    await new Promise((resolve, reject) => {
      uploadStream.on("finish", resolve)
      uploadStream.on("error", reject)
    })

    res.json({ success: true, downloadSlug, actualSize: req.file.size })
  } catch (err) {
    console.error("Upload error:", err)
    res.json({ success: false, message: err.message })
  }
})

app.get("/api/download/:slug", async (req, res) => {
  try {
    const metadata = await FileMetadata.findOne({ downloadSlug: req.params.slug })
    if (!metadata) {
      return res.status(404).json({ error: "File not found" })
    }

    res.setHeader("Content-Disposition", `attachment; filename="${metadata.originalName}"`)
    res.setHeader("Content-Type", metadata.mimeType)
    res.setHeader("Content-Length", metadata.size)

    await FileMetadata.updateOne({ _id: metadata._id }, { $inc: { downloadCount: 1 } })

    const db = cachedDb || mongoose.connection.getClient().db()
    const gridFSBucket = new GridFSBucket(db)
    const downloadStream = gridFSBucket.openDownloadStreamByName(req.params.slug)

    downloadStream.pipe(res)
  } catch (err) {
    console.error("Download error:", err)
    res.status(500).json({ error: err.message })
  }
})

app.get("/api/file/:slug", async (req, res) => {
  try {
    const metadata = await FileMetadata.findOne({ downloadSlug: req.params.slug })
    if (!metadata) {
      return res.status(404).json({ error: "File not found" })
    }
    res.json(metadata)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/api/user/profile", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select("-password")
    res.json({ success: true, user })
  } catch (err) {
    res.json({ success: false, message: err.message })
  }
})

app.get("/api/user/files", requireAuth, async (req, res) => {
  try {
    const files = await FileMetadata.find({ uploaderId: req.session.userId })
    res.json({ success: true, files })
  } catch (err) {
    res.json({ success: false, message: err.message })
  }
})

// Admin Routes
app.get("/api/admin/stats", async (req, res) => {
  try {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }
    const [totalUsers, totalFiles, siteStats] = await Promise.all([
      User.countDocuments(),
      FileMetadata.countDocuments(),
      SiteStats.findOne(),
    ])

    res.json({
      totalUsers,
      totalFiles,
      totalViews: siteStats ? siteStats.totalViews : 0,
    })
  } catch (err) {
    res.json({ error: err.message })
  }
})

app.get("/api/admin/files", async (req, res) => {
  try {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }
    const files = await FileMetadata.find().sort({ uploadDate: -1 })
    res.json(files)
  } catch (err) {
    res.json({ error: err.message })
  }
})

app.get("/api/admin/users", async (req, res) => {
  try {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }
    const users = await User.find().select("-password")
    res.json(users)
  } catch (err) {
    res.json({ error: err.message })
  }
})

app.delete("/api/admin/file/:id", async (req, res) => {
  try {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }
    const metadata = await FileMetadata.findByIdAndDelete(req.params.id)
    if (metadata) {
      const db = cachedDb || mongoose.connection.getClient().db()
      const gridFSBucket = new GridFSBucket(db)
      const files = await gridFSBucket.find({ filename: metadata.filename }).toArray()
      for (const file of files) {
        await gridFSBucket.delete(file._id)
      }
    }
    res.json({ success: true })
  } catch (err) {
    res.json({ error: err.message })
  }
})

app.post("/api/admin/ban/:id", async (req, res) => {
  try {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }
    const { isBanned } = req.body
    await User.findByIdAndUpdate(req.params.id, { isBanned })
    res.json({ success: true })
  } catch (err) {
    res.json({ error: err.message })
  }
})

app.get("/api/admin/leaderboard", async (req, res) => {
  try {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }
    const topFiles = await FileMetadata.find().sort({ downloadCount: -1 }).limit(10)
    const topUploaders = await FileMetadata.aggregate([
      { $group: { _id: "$uploaderName", totalDownloads: { $sum: "$downloadCount" }, fileCount: { $sum: 1 } } },
      { $sort: { totalDownloads: -1 } },
      { $limit: 10 },
    ])
    res.json({ topFiles, topUploaders })
  } catch (err) {
    res.json({ error: err.message })
  }
})

// Page Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/landing.html"))
})

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"))
})

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/login.html"))
})

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/signup.html"))
})

app.get("/profile", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/profile.html"))
})

app.get("/upload", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/upload.html"))
})

app.get("/file/:slug", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/file.html"))
})

app.get("/leaderboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/leaderboard.html"))
})

app.get("/view/:slug", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/view.html"))
})

app.get("/lostboy123", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/admin.html"))
})

app.get("/_hidden_nexdrop_admin_9834", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/hidden-admin.html"))
})

app.get("/404", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/404.html"))
})

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/404.html"))
})

module.exports = app
