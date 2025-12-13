const express = require("express")
const mongoose = require("mongoose")
const { GridFSBucket } = require("mongodb")
const multer = require("multer")
const path = require("path")
const fs = require("fs")
const crypto = require("crypto")
const session = require("express-session")

const app = express()

const uploadDir = process.env.VERCEL ? "/tmp/uploads" : path.join(__dirname, "uploads")
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true })
}

const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const downloadSlug = crypto.randomBytes(16).toString("hex")
    req.downloadSlug = downloadSlug
    cb(null, downloadSlug)
  },
})

const uploadMemory = multer({ storage: multer.memoryStorage() })
const uploadDisk = multer({ storage: diskStorage })

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
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    },
    name: "nexdrop.sid",
    rolling: true,
  }),
)

// MongoDB Connection
let db
let gridFSBucket
let isConnected = false
let connectionPromise = null

async function connectDatabase() {
  if (isConnected && mongoose.connection.readyState === 1) {
    console.log("[v0] Using existing MongoDB connection")
    return true
  }

  if (connectionPromise) {
    console.log("[v0] Waiting for existing connection attempt")
    return connectionPromise
  }

  connectionPromise = (async () => {
    try {
      const MONGODB_URI =
        process.env.MONGODB_URI ||
        "mongodb+srv://lostboytech1:n1n2nanaagye@cluster0.yqp30.mongodb.net/nexdrop?retryWrites=true&w=majority&appName=nexdrop"

      if (!MONGODB_URI) {
        throw new Error("MONGODB_URI is not defined")
      }

      console.log("[v0] Attempting MongoDB connection...")

      await mongoose.connect(MONGODB_URI, {
        maxPoolSize: 10,
        minPoolSize: 2,
        serverSelectionTimeoutMS: 30000,
        socketTimeoutMS: 75000,
        connectTimeoutMS: 30000,
        family: 4,
      })

      console.log("[v0] MongoDB connected successfully")
      const dbName = mongoose.connection.name || "nexdrop"
      console.log("[v0] Using database:", dbName)

      db = mongoose.connection.getClient().db(dbName)
      gridFSBucket = new GridFSBucket(db)
      isConnected = true

      await initializeAdmin()
      connectionPromise = null
      return true
    } catch (err) {
      console.error("[v0] MongoDB connection error:", err.message)
      console.error("[v0] Error details:", {
        name: err.name,
        code: err.code,
        uri: process.env.MONGODB_URI ? "Custom URI provided" : "Using fallback URI",
      })
      connectionPromise = null
      isConnected = false
      throw new Error(`Database connection failed: ${err.message}`)
    }
  })()

  return connectionPromise
}

mongoose.connection.on("disconnected", () => {
  console.log("MongoDB disconnected")
  isConnected = false
})

mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error:", err)
  isConnected = false
})

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
  storageType: { type: String, enum: ["gridfs", "disk"], default: "gridfs" },
})

const User = mongoose.model("User", userSchema)
const FileMetadata = mongoose.model("FileMetadata", fileMetadataSchema)

const siteStatsSchema = new mongoose.Schema({
  totalViews: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now },
})
const SiteStats = mongoose.model("SiteStats", siteStatsSchema)

const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, message: "Not authenticated" })
  }
  next()
}

async function initializeAdmin() {
  try {
    console.log("[v0] Checking for admin user...")
    const adminExists = await User.findOne({ username: "nex" })
    if (!adminExists) {
      const hashedPassword = crypto.createHash("sha256").update("n1n2nanaagye").digest("hex")
      await User.create({
        username: "nex",
        email: "admin@nexdrop.com",
        password: hashedPassword,
        isAdmin: true,
      })
      console.log("[v0] Admin user 'nex' created successfully")
    } else {
      console.log("[v0] Admin user already exists")
    }
  } catch (err) {
    console.error("[v0] Admin initialization error:", err.message)
  }
}

app.use(async (req, res, next) => {
  try {
    const connected = await connectDatabase()
    if (!connected) {
      throw new Error("Failed to establish database connection")
    }
    next()
  } catch (err) {
    console.error("[v0] Database middleware error:", err.message)
    res.status(503).json({
      error: "Database service unavailable",
      message: "Unable to connect to MongoDB. Please check your MONGODB_URI environment variable.",
      details: process.env.NODE_ENV === "development" ? err.message : undefined,
    })
  }
})

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
app.post("/api/upload/small", uploadMemory.single("file"), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ success: false, message: "Not authenticated" })
    }
    if (!req.file) {
      return res.json({ success: false, message: "No file provided" })
    }
    const MAX_SIZE = 10 * 1024 * 1024
    if (req.file.size > MAX_SIZE) {
      return res.json({
        success: false,
        message: "File exceeds 10MB limit for this upload method. Use large file upload.",
      })
    }
    if (req.file.buffer.length > MAX_SIZE) {
      return res.json({ success: false, message: "File exceeds 10MB limit" })
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
      storageType: "gridfs",
    })

    res.json({ success: true, downloadSlug, actualSize: req.file.size })

    const uploadStream = gridFSBucket.openUploadStream(downloadSlug, {
      metadata: { originalName: req.file.originalname },
    })

    uploadStream.on("error", (err) => {
      console.error("Upload stream error:", err)
      FileMetadata.findByIdAndDelete(fileMetadata._id).catch(console.error)
    })

    uploadStream.end(req.file.buffer)
  } catch (err) {
    res.json({ success: false, message: err.message })
  }
})

app.post("/api/upload/large", uploadDisk.single("file"), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ success: false, message: "Not authenticated" })
    }
    if (!req.file) {
      return res.json({ success: false, message: "No file provided" })
    }

    const downloadSlug = req.downloadSlug || req.file.filename

    const fileMetadata = await FileMetadata.create({
      filename: downloadSlug,
      originalName: req.file.originalname,
      uploaderId: req.session.userId,
      uploaderName: req.session.username,
      size: req.file.size,
      mimeType: req.file.mimetype,
      downloadSlug,
      visibility: "public",
      storageType: "disk",
    })

    res.json({ success: true, downloadSlug, actualSize: req.file.size })
  } catch (err) {
    if (req.file && req.file.path) {
      fs.unlink(req.file.path, (unlinkErr) => {
        if (unlinkErr) console.error("Error deleting file:", unlinkErr)
      })
    }
    res.json({ success: false, message: err.message })
  }
})

app.post("/api/upload", (req, res, next) => {
  uploadMemory.single("file")(req, res, async (err) => {
    if (err) {
      return res.json({ success: false, message: err.message })
    }

    if (!req.file) {
      return res.json({ success: false, message: "No file provided" })
    }

    const TEN_MB = 10 * 1024 * 1024

    if (req.file.size <= TEN_MB) {
      try {
        if (!req.session.userId) {
          return res.json({ success: false, message: "Not authenticated" })
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
          storageType: "gridfs",
        })

        res.json({ success: true, downloadSlug, actualSize: req.file.size })

        const uploadStream = gridFSBucket.openUploadStream(downloadSlug, {
          metadata: { originalName: req.file.originalname },
        })

        uploadStream.on("error", (err) => {
          console.error("Upload stream error:", err)
          FileMetadata.findByIdAndDelete(fileMetadata._id).catch(console.error)
        })

        uploadStream.end(req.file.buffer)
      } catch (err) {
        res.json({ success: false, message: err.message })
      }
    } else {
      res.json({
        success: false,
        useLargeUpload: true,
        message: "File exceeds 10MB. Please use the large file upload method.",
      })
    }
  })
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
      const filePath = path.join(uploadDir, metadata.filename)
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found on disk" })
      }
      const fileStream = fs.createReadStream(filePath)
      fileStream.on("error", (err) => {
        console.error("File read error:", err)
        res.status(500).json({ error: "Download error" })
      })
      fileStream.pipe(res)
    } else {
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
      if (metadata.storageType === "disk") {
        const filePath = path.join(uploadDir, metadata.filename)
        fs.unlink(filePath, (err) => {
          if (err) console.error("Error deleting file from disk:", err)
        })
      } else {
        gridFSBucket.delete(new mongoose.Types.ObjectId(metadata._id))
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

if (process.env.VERCEL) {
  module.exports = app
} else {
  async function startServer() {
    await connectDatabase()
    const PORT = process.env.PORT || 3000
    app.listen(PORT, () => console.log(`NexDrop running on http://localhost:${PORT}`))
  }
  startServer()
}
