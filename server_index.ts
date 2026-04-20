import express, { Request, Response, NextFunction } from "express";
import compression from "compression";
import session from "express-session";
import passport from "passport";
import path from "path";
import { fileURLToPath } from "url";
import { db, testConnection } from "./db";
import { registerRoutes } from "./routes";
import { registerAuthRoutes } from "./auth";
import { setupVite, serveStatic } from "./vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.on("unhandledRejection", (reason: any) => {
  if (reason?.code === "57P01" || reason?.message?.includes("terminating connection")) {
    console.log("Database connection terminated - will auto-reconnect");
    return;
  }
  console.error("Unhandled Rejection:", reason);
});

const app = express();

app.use(compression());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "rofithack-dev-secret-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/healthz", (_req: Request, res: Response) => {
  res.status(200).send("OK");
});

app.get("/health", async (_req: Request, res: Response) => {
  try {
    await testConnection();
    res.status(200).json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      services: {
        database: "connected",
        server: "running",
      },
    });
  } catch (error) {
    res.status(503).json({
      status: "unhealthy",
      timestamp: new Date().toISOString(),
      error: "Database connection failed",
    });
  }
});

app.get("/readyz", async (_req: Request, res: Response) => {
  try {
    await testConnection();
    res.status(200).send("READY");
  } catch {
    res.status(503).send("NOT READY");
  }
});

let bootstrapReady = false;
let bootstrapProgress = 0;
let bootstrapMessage = "Starting up...";

app.get("/api/bootstrap-status", (_req: Request, res: Response) => {
  res.json({
    ready: bootstrapReady,
    pagesLoaded: bootstrapReady,
    componentsLoaded: bootstrapReady,
    progress: bootstrapProgress,
    message: bootstrapMessage,
  });
});

async function initializeApp() {
  console.log("🚀 ROFITHACK AI - Starting Server...");
  
  bootstrapMessage = "Connecting to database...";
  bootstrapProgress = 20;

  try {
    await testConnection();
    console.log("✅ Database connected");
    bootstrapProgress = 40;
    bootstrapMessage = "Loading routes...";
  } catch (error) {
    console.error("❌ Database connection failed:", error);
    bootstrapMessage = "Database connection failed - running in limited mode";
  }

  try {
    registerAuthRoutes(app);
    await registerRoutes(app);
    console.log("✅ Routes registered");
    bootstrapProgress = 60;
    bootstrapMessage = "Setting up frontend...";
  } catch (error) {
    console.error("❌ Route registration failed:", error);
  }

  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    await setupVite(app);
  }

  bootstrapProgress = 80;
  bootstrapMessage = "Finalizing...";

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error("Server error:", err);
    res.status(500).json({
      error: "Internal server error",
      message: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  });

  const PORT = parseInt(process.env.PORT || "5000", 10);
  
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`   Health: http://localhost:${PORT}/health`);
    console.log(`   App: http://localhost:${PORT}`);
    
    bootstrapReady = true;
    bootstrapProgress = 100;
    bootstrapMessage = "Ready!";
  });
}

initializeApp().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});

export { app };
