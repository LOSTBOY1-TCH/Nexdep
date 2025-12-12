const express = require("express")
const mongoose = require("mongoose")
const { GridFSBucket } = require("mongodb")
const multer = require("multer")
const path = require("path")
const fs = require("fs")
const crypto = require("crypto")
const session = require("express-session")
require("dotenv").config()

const app = express()
const upload = multer({ storage: multer.memoryStorage() })

app.set("trust proxy", 1)

// Middleware
app.use(express.static("public"))
app.use(express.json({ limit: "100mb" }))
app.use(express.urlencoded({ limit: "100mb", extended: true }))

app.use(
  session({
    secret: process.env.SESSION_SECRET || "nexdrop-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    },
    name: "nexdrop.sid",
    rolling: true, // Reset expiration on every request
  }),
)

// MongoDB Connection
let db
let gridFSBucket

mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/nexdrop", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB connected")
    db = mongoose.connection.getClient().db("nexdrop")
    gridFSBucket = new GridFSBucket(db)
    initializeAdmin()
  })
  .catch((err) => console.log("MongoDB connection error:", err))

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
})

const User = mongoose.model("User", userSchema)
const FileMetadata = mongoose.model("FileMetadata", fileMetadataSchema)

// Site Stats Schema
const siteStatsSchema = new mongoose.Schema({
  totalViews: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now },
})
const SiteStats = mongoose.model("SiteStats", siteStatsSchema)

// Authentication Middleware Function
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, message: "Not authenticated" })
  }
  next()
}

// Initialize Admin
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
      console.log("Admin user created")
    }
  } catch (err) {
    console.log("Admin initialization error:", err)
  }
}

// Routes - Auth
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

    req.session.save((err) => {
      if (err) {
        console.error("[v0] Session save error:", err)
        return res.json({ success: false, message: "Session error" })
      }
      console.log("[v0] Signup session saved:", { userId: user._id, username: user.username })
      res.json({ success: true, redirect: "/dashboard" })
    })
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

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err)
        return res.json({ success: false, message: "Session error" })
      }
      res.json({ success: true, redirect: "/dashboard" })
    })
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

// Routes - File Operations
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ success: false, message: "Not authenticated" })
    }
    if (!req.file) {
      return res.json({ success: false, message: "No file provided" })
    }
    const MAX_SIZE = 5 * 1024 * 1024 * 1024 // 5GB
    if (req.file.size > MAX_SIZE) {
      return res.json({ success: false, message: "File exceeds 5GB limit" })
    }
    if (req.file.buffer.length > MAX_SIZE) {
      return res.json({ success: false, message: "File exceeds 5GB limit" })
    }

    const downloadSlug = crypto.randomBytes(16).toString("hex")

    const fileMetadata = await FileMetadata.create({
      filename: downloadSlug,
      originalName: req.file.originalname,
      uploaderId: req.session.userId,
      uploaderName: req.session.username,
      size: req.file.size,
      mimeType: req.file.mimetype,
      downloadSlug,
      visibility: "public",
    })

    res.json({ success: true, downloadSlug, actualSize: req.file.size })

    const uploadStream = gridFSBucket.openUploadStream(downloadSlug, {
      metadata: { originalName: req.file.originalname },
    })

    uploadStream.on("error", (err) => {
      console.error("Upload stream error:", err)
      // Delete metadata if upload fails
      FileMetadata.findByIdAndDelete(fileMetadata._id).catch(console.error)
    })

    uploadStream.end(req.file.buffer)
  } catch (err) {
    res.json({ success: false, message: err.message })
  }
})

app.get("/api/download/:slug", async (req, res) => {
  try {
    const metadata = await FileMetadata.findOne({ downloadSlug: req.params.slug })
    if (!metadata) {
      return res.status(404).json({ error: "File not found" })
    }

    const downloadStream = gridFSBucket.openDownloadStreamByName(req.params.slug)

    res.setHeader("Content-Disposition", `attachment; filename="${metadata.originalName}"`)
    res.setHeader("Content-Type", metadata.mimeType)
    res.setHeader("Content-Length", metadata.size)

    await FileMetadata.updateOne({ _id: metadata._id }, { $inc: { downloadCount: 1 } })

    downloadStream.on("error", (err) => {
      console.error("Download stream error:", err)
      res.status(500).json({ error: "Download error" })
    })

    downloadStream.pipe(res)
  } catch (err) {
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

// Routes - User
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

// Routes - Admin
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

    const stats = {
      totalUsers,
      totalFiles,
      totalViews: siteStats || { totalViews: 0 },
    }
    res.json(stats)
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
      gridFSBucket.delete(new mongoose.Types.ObjectId(metadata._id))
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

// Routes - Public
app.get("/api/views", async (req, res) => {
  try {
    let stats = await SiteStats.findOne()
    if (!stats) {
      stats = await SiteStats.create({ totalViews: 1 })
    } else {
      stats.totalViews += 1
      await stats.save()
    }
    res.json({ views: stats.totalViews })
  } catch (err) {
    res.json({ error: err.message })
  }
})

app.get("/api/search", async (req, res) => {
  try {
    const query = req.query.q || ""
    const files = await FileMetadata.find({
      $or: [{ originalName: { $regex: query, $options: "i" } }, { tags: { $in: [new RegExp(query, "i")] } }],
    })
    res.json(files)
  } catch (err) {
    res.json({ error: err.message })
  }
})

// Serve HTML pages
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/landing.html"))
})

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"))
})

app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public/login.html")))
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "public/signup.html")))
app.get("/profile", (req, res) => {
  res.sendFile(path.join(__dirname, "public/profile.html"))
})
app.get("/upload", (req, res) => {
  res.sendFile(path.join(__dirname, "public/upload.html"))
})
app.get("/file/:slug", (req, res) => res.sendFile(path.join(__dirname, "public/file.html")))
app.get("/leaderboard", (req, res) => res.sendFile(path.join(__dirname, "public/leaderboard.html")))
app.get("/view/:slug", (req, res) => res.sendFile(path.join(__dirname, "public/view.html")))

app.get("/lostboy123", (req, res) => {
  res.sendFile(path.join(__dirname, "public/admin.html"))
})

app.get("/_hidden_nexdrop_admin_9834", (req, res) => {
  res.sendFile(path.join(__dirname, "public/hidden-admin.html"))
})

app.get("/404", (req, res) => res.sendFile(path.join(__dirname, "public/404.html")))
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public/404.html")))

// Start Server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`NexDrop running on http://localhost:${PORT}`))
