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

const uploadDir = path.join(__dirname, "uploads")
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true })
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const uniqueName = crypto.randomBytes(16).toString("hex") + path.extname(file.originalname)
    cb(null, uniqueName)
  },
})

const upload = multer({ storage: storage })

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

async function connectDatabase() {
  try {
    await mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/nexdrop", {
      serverSelectionTimeoutMS: 30000, // Increase timeout to 30 seconds
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4, skip trying IPv6
    })
    console.log("MongoDB connected successfully")
    db = mongoose.connection.getClient().db("nexdrop")
    gridFSBucket = new GridFSBucket(db)
    await initializeAdmin()
    return true
  } catch (err) {
    console.error("MongoDB connection error:", err)
    console.error("Make sure MongoDB is running and MONGODB_URI is correct")
    process.exit(1) // Exit if database connection fails
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
  storageType: { type: String, enum: ["gridfs", "disk"], default: "gridfs" }, // New field
  filePath: String, // New field for disk storage path
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
      // Clean up the uploaded file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path)
      }
      return res.json({ success: false, message: "File exceeds 5GB limit" })
    }

    const downloadSlug = crypto.randomBytes(16).toString("hex")
    const TEN_MB = 10 * 1024 * 1024

    // Determine storage type based on file size
    const storageType = req.file.size > TEN_MB ? "disk" : "gridfs"

    const fileMetadata = await FileMetadata.create({
      filename: storageType === "disk" ? req.file.filename : downloadSlug,
      originalName: req.file.originalname,
      uploaderId: req.session.userId,
      uploaderName: req.session.username,
      size: req.file.size,
      mimeType: req.file.mimetype,
      downloadSlug,
      visibility: "public",
      storageType,
      filePath: storageType === "disk" ? req.file.path : null,
    })

    if (storageType === "gridfs") {
      // For files < 10MB, read from disk and store in GridFS
      const fileBuffer = fs.readFileSync(req.file.path)

      const uploadStream = gridFSBucket.openUploadStream(downloadSlug, {
        metadata: { originalName: req.file.originalname },
      })

      uploadStream.on("error", (err) => {
        console.error("Upload stream error:", err)
        FileMetadata.findByIdAndDelete(fileMetadata._id).catch(console.error)
      })

      uploadStream.on("finish", () => {
        // Delete the temporary file after uploading to GridFS
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path)
        }
      })

      uploadStream.end(fileBuffer)
    }
    // For files > 10MB, they stay on disk (already saved by multer)

    console.log(`[v0] File uploaded: ${req.file.originalname}, Size: ${req.file.size} bytes, Storage: ${storageType}`)

    res.json({
      success: true,
      downloadSlug,
      actualSize: req.file.size,
      storageType,
      message: storageType === "disk" ? "File stored permanently on server" : "File uploaded successfully",
    })
  } catch (err) {
    // Clean up file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path)
    }
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

    if (metadata.storageType === "disk") {
      // Stream from disk for large files
      if (!fs.existsSync(metadata.filePath)) {
        return res.status(404).json({ error: "File not found on disk" })
      }
      const fileStream = fs.createReadStream(metadata.filePath)
      fileStream.on("error", (err) => {
        console.error("File stream error:", err)
        res.status(500).json({ error: "Download error" })
      })
      fileStream.pipe(res)
    } else {
      // Stream from GridFS for small files
      const downloadStream = gridFSBucket.openDownloadStreamByName(req.params.slug)
      downloadStream.on("error", (err) => {
        console.error("Download stream error:", err)
        res.status(500).json({ error: "Download error" })
      })
      downloadStream.pipe(res)
    }
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
    const metadata = await FileMetadata.findById(req.params.id)
    if (metadata) {
      if (metadata.storageType === "gridfs") {
        // Only delete GridFS files (< 10MB)
        try {
          const files = await db.collection("fs.files").find({ filename: metadata.filename }).toArray()
          if (files.length > 0) {
            await gridFSBucket.delete(files[0]._id)
          }
        } catch (err) {
          console.error("GridFS delete error:", err)
        }
      } else {
        // Files > 10MB stored on disk are NOT deleted - they remain permanent
        console.log(`[v0] Skipping deletion of disk file: ${metadata.originalName} (permanent storage)`)
      }
      // Delete metadata from database
      await FileMetadata.findByIdAndDelete(req.params.id)
    }
    res.json({ success: true, message: "File record deleted (large files remain on disk)" })
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
async function startServer() {
  await connectDatabase()
  const PORT = process.env.PORT || 3000
  app.listen(PORT, () => console.log(`NexDrop running on http://localhost:${PORT}`))
}

startServer()
