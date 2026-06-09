import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import crypto from "crypto";
import UAParser from "ua-parser-js";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ─── DB ────────────────────────────────────────────────────────────────────
const client = new MongoClient(process.env.MONGO_URI || "mongodb://localhost:27017");
const db = () => client.db("synq_vendors");
const vendors = () => db().collection("vendors");
const scans = () => db().collection("scan_logs");

// ─── Helpers ───────────────────────────────────────────────────────────────
const generateVendorId = (firstName, lastName) => {
  const base = `${firstName}${lastName}`.toLowerCase().replace(/[^a-z0-9]/g, "");
  const suffix = crypto.randomBytes(3).toString("hex");
  return `${base}_${suffix}`;
};

const getClientIP = (req) => {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.socket.remoteAddress
  );
};

const hashIP = (ip) =>
  crypto
    .createHash("sha256")
    .update(ip + (process.env.IP_SALT || "synq2024"))
    .digest("hex")
    .slice(0, 16);

const computeFraudScore = async (vendorId, ipHash, userAgent, timezone) => {
  const flags = [];
  let score = 0;

  const vendorDoc = await vendors().findOne({ vendorId });
  if (vendorDoc) {
    const recentScan = await scans().findOne({
      vendorId,
      ipHash,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    });
    if (recentScan) {
      flags.push("VENDOR_IP_RESCAN");
      score += 60;
    }
  }

  const recentMultiVendor = await scans().countDocuments({
    ipHash,
    createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) },
  });
  if (recentMultiVendor >= 3) {
    flags.push("HIGH_FREQUENCY_IP");
    score += 25;
  }

  const ua = new UAParser(userAgent);
  const deviceType = ua.getDevice().type;
  if (!userAgent || userAgent.length < 20) {
    flags.push("MISSING_USER_AGENT");
    score += 30;
  }
  if (!deviceType) {
    flags.push("NON_MOBILE_DEVICE");
    score += 15;
  }

  if (timezone && !timezone.includes("Asia") && !timezone.includes("Kolkata")) {
    flags.push("TIMEZONE_MISMATCH");
    score += 10;
  }

  const verdict = score >= 60 ? "FAKE" : score >= 30 ? "SUSPICIOUS" : "REAL";
  return { score: Math.min(score, 100), flags, verdict };
};

// ─── ROUTES ────────────────────────────────────────────────────────────────

app.post("/api/vendors/onboard", async (req, res) => {
  try {
    const { firstName, lastName, gender, age, email } = req.body;

    if (!firstName || !lastName || !email) {
      return res.status(400).json({ success: false, error: "firstName, lastName and email are required" });
    }
    if (age && (isNaN(age) || age < 16 || age > 100)) {
      return res.status(400).json({ success: false, error: "Invalid age" });
    }

    const existing = await vendors().findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ success: false, error: "Email already registered", vendorId: existing.vendorId });
    }

    const vendorId = generateVendorId(firstName, lastName);
    const BASE_URL = process.env.BASE_URL || "https://synq-vendor.trustgrid.com";

    const vendorDoc = {
      vendorId,
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      gender: gender || null,
      age: age ? parseInt(age) : null,
      email: email.toLowerCase().trim(),
      username: null,
      status: "active",
      createdAt: new Date(),
      updatedAt: new Date(),
      dashboardUrl: `${BASE_URL}/v/${vendorId}`,
      qrCodeUrl: `${BASE_URL}/qr/${vendorId}`,
      scanRedirectUrl: `${BASE_URL}/scan/${vendorId}`,
      totalScans: 0,
      realDownloads: 0,
      fakeDownloads: 0,
      suspiciousDownloads: 0,
      commission: 0,
    };

    await vendors().insertOne(vendorDoc);

    return res.status(201).json({
      success: true,
      message: "Vendor onboarded successfully",
      data: {
        vendorId,
        dashboardUrl: vendorDoc.dashboardUrl,
        qrCodeUrl: vendorDoc.qrCodeUrl,
        scanRedirectUrl: vendorDoc.scanRedirectUrl,
      },
    });
  } catch (err) {
    console.error("Onboard error:", err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// GET /api/vendors — list all vendors (dashboard)
app.get("/api/vendors", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const list = await vendors()
      .find(
        {},
        {
          projection: {
            _id: 0,
            email: 1,
            vendorId: 1,
            firstName: 1,
            lastName: 1,
            totalScans: 1,
            realDownloads: 1,
            fakeDownloads: 1,
            suspiciousDownloads: 1,
            commission: 1,
            createdAt: 1,
            status: 1,
          },
        }
      )
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();
    res.json({ success: true, data: list });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// GET /api/vendors/:vendorId — single vendor profile
app.get("/api/vendors/:vendorId", async (req, res) => {
  try {
    const vendor = await vendors().findOne(
      { vendorId: req.params.vendorId },
      { projection: { _id: 0, email: 0 } }
    );
    if (!vendor) return res.status(404).json({ success: false, error: "Vendor not found" });
    res.json({ success: true, data: vendor });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// GET /api/scan-init/:vendorId — called by scan.html via fetch; logs scan, returns scanId + storeUrl as JSON
app.get("/api/scan-init/:vendorId", async (req, res) => {
  try {
    const { vendorId } = req.params;

    const vendor = await vendors().findOne({ vendorId });
    if (!vendor || vendor.status !== "active") {
      return res.status(404).json({ success: false, error: "Vendor not found" });
    }

    const ip = getClientIP(req);
    const ipHash = hashIP(ip);
    const userAgent = req.headers["user-agent"] || "";
    const timezone = req.query.tz || "";
    const screenSize = req.query.sc || "";

    const { score, flags, verdict } = await computeFraudScore(vendorId, ipHash, userAgent, timezone);

    const ua = new UAParser(userAgent);
    const platform = ua.getOS().name?.toLowerCase() || "";

    const scanLog = {
      vendorId, ipHash, userAgent,
      os: ua.getOS().name,
      device: ua.getDevice().type || "desktop",
      browser: ua.getBrowser().name,
      screenSize, timezone,
      fraudScore: score, fraudFlags: flags, verdict,
      downloadConfirmed: false, username: null,
      createdAt: new Date(),
    };
    const { insertedId } = await scans().insertOne(scanLog);

    await vendors().updateOne(
      { vendorId },
      { $inc: { totalScans: 1 }, $set: { updatedAt: new Date() } }
    );

    let storeUrl;
    if (platform.includes("android")) {
      storeUrl = `https://play.google.com/store/search?q=synq+social&c=apps&hl=en_IN&referrer=vendor_${vendorId}`;
    } else if (platform.includes("ios") || platform.includes("iphone") || platform.includes("ipad")) {
      storeUrl = `https://apps.apple.com/in/app/synq-social/id6745467461`;
    } else {
      storeUrl = null; // desktop: no store redirect, just confirm page
    }

    res.json({
      success: true,
      scanId: insertedId.toString(),
      storeUrl,
      verdict,
      fraudScore: score,
    });
  } catch (err) {
    console.error("Scan init error:", err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// GET /go/:vendorId — QR scan redirect + fraud logging
app.get("/go/:vendorId", async (req, res) => {
  try {
    const { vendorId } = req.params;

    const vendor = await vendors().findOne({ vendorId });
    if (!vendor || vendor.status !== "active") {
      return res.redirect("https://synq-vendor.trustgrid.com");
    }

    const ip = getClientIP(req);
    const ipHash = hashIP(ip);
    const userAgent = req.headers["user-agent"] || "";
    const timezone = req.query.tz || "";
    const screenSize = req.query.sc || "";

    const { score, flags, verdict } = await computeFraudScore(vendorId, ipHash, userAgent, timezone);

    const ua = new UAParser(userAgent);
    const platform = ua.getOS().name?.toLowerCase() || "";

    const scanLog = {
      vendorId,
      ipHash,
      userAgent,
      os: ua.getOS().name,
      device: ua.getDevice().type || "desktop",
      browser: ua.getBrowser().name,
      screenSize,
      timezone,
      fraudScore: score,
      fraudFlags: flags,
      verdict,
      downloadConfirmed: false,
      username: null,
      createdAt: new Date(),
    };
    const { insertedId } = await scans().insertOne(scanLog);

    await vendors().updateOne(
      { vendorId },
      { $inc: { totalScans: 1 }, $set: { updatedAt: new Date() } }
    );

    let storeUrl;
    if (platform.includes("android")) {
      storeUrl = `https://play.google.com/store/search?q=synq+social&c=apps&hl=en_IN&referrer=vendor_${vendorId}`;
    } else if (platform.includes("ios") || platform.includes("iphone") || platform.includes("ipad")) {
      storeUrl = `https://apps.apple.com/in/app/synq-social/id6745467461?pt=vendor_${vendorId}`;
    } else {
      storeUrl = `https://synq-vendor.trustgrid.com/download?ref=${vendorId}`;
    }

    const scanIdStr = insertedId.toString();
    const separator = storeUrl.includes("?") ? "&" : "?";
    res.redirect(302, `${storeUrl}${separator}_scan=${scanIdStr}`);
  } catch (err) {
    console.error("Scan redirect error:", err);
    res.redirect("https://synq-vendor.trustgrid.com");
  }
});

// POST /api/scans/:scanId/confirm — lock username after download
app.post("/api/scans/:scanId/confirm", async (req, res) => {
  try {
    const { scanId } = req.params;
    const { username } = req.body;

    if (!username || username.trim().length < 3) {
      return res.status(400).json({ success: false, error: "Username must be at least 3 characters" });
    }

    let scanObjId;
    try {
      scanObjId = new ObjectId(scanId);
    } catch {
      return res.status(400).json({ success: false, error: "Invalid scan ID" });
    }

    const scan = await scans().findOne({ _id: scanObjId });
    if (!scan) return res.status(404).json({ success: false, error: "Scan not found" });
    if (scan.downloadConfirmed) {
      return res.status(409).json({ success: false, error: "Username already locked for this scan" });
    }

    const usernameExists = await scans().findOne({
      username: username.trim().toLowerCase(),
      downloadConfirmed: true,
    });
    if (usernameExists) {
      return res.status(409).json({ success: false, error: "Username already taken by another download" });
    }

    const finalVerdict = scan.verdict === "FAKE" ? "FAKE" : "REAL";

    await scans().updateOne(
      { _id: scanObjId },
      {
        $set: {
          downloadConfirmed: true,
          username: username.trim().toLowerCase(),
          verdict: finalVerdict,
          confirmedAt: new Date(),
        },
      }
    );

    const incField = finalVerdict === "REAL" ? "realDownloads" : "fakeDownloads";
    const commissionDelta = finalVerdict === "REAL" ? 1 : 0;
    await vendors().updateOne(
      { vendorId: scan.vendorId },
      { $inc: { [incField]: 1, commission: commissionDelta }, $set: { updatedAt: new Date() } }
    );

    res.json({
      success: true,
      message: "Download confirmed and username locked",
      data: {
        scanId,
        username: username.trim().toLowerCase(),
        verdict: finalVerdict,
        isFlaggedFake: finalVerdict === "FAKE",
      },
    });
  } catch (err) {
    console.error("Confirm error:", err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// GET /api/vendors/:vendorId/scans — paginated scan list
app.get("/api/vendors/:vendorId/scans", async (req, res) => {
  try {
    const { vendorId } = req.params;
    const { verdict, page = 1, limit = 20 } = req.query;

    const filter = { vendorId };
    if (verdict) filter.verdict = verdict.toUpperCase();

    const total = await scans().countDocuments(filter);
    const results = await scans()
      .find(filter, { projection: { ipHash: 0 } })
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .toArray();

    res.json({
      success: true,
      data: results,
      pagination: { page: parseInt(page), limit: parseInt(limit), total },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// PATCH /api/vendors/:vendorId/scans/:scanId/flag — admin manual override
app.patch("/api/vendors/:vendorId/scans/:scanId/flag", async (req, res) => {
  try {
    const { vendorId, scanId } = req.params;
    const { verdict, reason } = req.body;

    if (!["FAKE", "REAL", "SUSPICIOUS"].includes(verdict)) {
      return res.status(400).json({ success: false, error: "verdict must be FAKE, REAL, or SUSPICIOUS" });
    }

    const scan = await scans().findOne({ _id: new ObjectId(scanId), vendorId });
    if (!scan) return res.status(404).json({ success: false, error: "Scan not found" });

    const previousVerdict = scan.verdict;
    await scans().updateOne(
      { _id: new ObjectId(scanId) },
      {
        $set: {
          verdict,
          manualOverride: true,
          overrideReason: reason || "Admin override",
          overriddenAt: new Date(),
        },
        $push: { fraudFlags: `MANUAL_${verdict}` },
      }
    );

    if (previousVerdict !== verdict) {
      const decField = previousVerdict === "REAL" ? "realDownloads" : previousVerdict === "FAKE" ? "fakeDownloads" : "suspiciousDownloads";
      const incField = verdict === "REAL" ? "realDownloads" : verdict === "FAKE" ? "fakeDownloads" : "suspiciousDownloads";
      const commissionDelta = (previousVerdict === "REAL" ? -1 : 0) + (verdict === "REAL" ? 1 : 0);
      await vendors().updateOne(
        { vendorId },
        {
          $inc: { [decField]: -1, [incField]: 1, commission: commissionDelta },
          $set: { updatedAt: new Date() },
        }
      );
    }

    res.json({ success: true, message: `Scan flagged as ${verdict}` });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// GET /scan/:vendorId — QR lands here first; JS captures tz+screen then calls /go/:vendorId
app.get("/scan/:vendorId", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "scan.html"));
});

// GET /v/:vendorId — vendor-facing confirmation page (enter username after download)
app.get("/v/:vendorId", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "vendor.html"));
});

// GET /download — non-mobile fallback (also shows vendor confirmation UI)
app.get("/download", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "vendor.html"));
});

// ─── Start ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
client.connect().then(() => {
  console.log("MongoDB connected");
  db().collection("vendors").createIndex({ vendorId: 1 }, { unique: true });
  db().collection("vendors").createIndex({ email: 1 }, { unique: true });
  db().collection("scan_logs").createIndex({ vendorId: 1, createdAt: -1 });
  db().collection("scan_logs").createIndex({ ipHash: 1, createdAt: -1 });
  db().collection("scan_logs").createIndex({ username: 1 });
  app.listen(PORT, () => console.log(`Synq Vendor API running on port ${PORT}`));
});

export default app;