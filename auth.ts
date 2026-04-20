import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bcrypt from "bcrypt";
import { storage } from "./storage";
import { Express } from "express";

// ── PASSPORT SETUP ────────────────────────────────────────
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: number, done) => {
  try {
    const user = await storage.getUser(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ── LOCAL STRATEGY (email + password) ────────────────────
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const user = await storage.getUserByEmail(email.toLowerCase());
      if (!user) return done(null, false, { message: "No account found with that email" });
      if (!user.password) return done(null, false, { message: "Please sign in with Google" });
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return done(null, false, { message: "Incorrect password" });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// ── GOOGLE STRATEGY ───────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${process.env.APP_URL || ""}/auth/google/callback`,
      },
      async (_at, _rt, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value || `${profile.id}@google.oauth`;
          const name = profile.displayName || email.split("@")[0];
          const avatar = profile.photos?.[0]?.value || null;

          // Find existing user or create
          let user = await storage.getUserByEmail(email);
          if (!user) {
            // Generate unique username from name
            const base = name.toLowerCase().replace(/[^a-z0-9]/g, "").substring(0, 15) || "user";
            let username = base;
            let i = 1;
            while (await storage.getUserByUsername(username)) {
              username = `${base}${i++}`;
            }
            user = await storage.createUser({
              username,
              email: email.toLowerCase(),
              profileImageUrl: avatar,
              isVerified: true,
            });
          }
          return done(null, user);
        } catch (err) {
          return done(err as Error);
        }
      }
    )
  );
}

// ── AUTH ROUTES ───────────────────────────────────────────
export function registerAuthRoutes(app: Express) {

  // ── SIGNUP ──────────────────────────────────────────────
  app.post("/api/auth/signup", async (req, res) => {
    try {
      const { email, password, username } = req.body;

      if (!email || !password || !username) {
        return res.status(400).json({ error: "Email, password and username are required" });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
      }

      // Check email
      const existingEmail = await storage.getUserByEmail(email.toLowerCase());
      if (existingEmail) return res.status(409).json({ error: "Email already registered" });

      // Check username
      const existingUsername = await storage.getUserByUsername(username);
      if (existingUsername) return res.status(409).json({ error: "Username already taken" });

      const hashed = await bcrypt.hash(password, 12);
      const user = await storage.createUser({
        email: email.toLowerCase(),
        password: hashed,
        username,
      });

      req.login(user, (err) => {
        if (err) return res.status(500).json({ error: "Login after signup failed" });
        const { password: _, ...safeUser } = user as any;
        res.json({ success: true, user: safeUser });
      });
    } catch (err: any) {
      console.error("Signup error:", err);
      res.status(500).json({ error: "Signup failed" });
    }
  });

  // ── LOGIN ───────────────────────────────────────────────
  app.post("/api/auth/login", (req, res, next) => {
    passport.authenticate("local", (err: any, user: any, info: any) => {
      if (err) return next(err);
      if (!user) return res.status(401).json({ error: info?.message || "Login failed" });
      req.login(user, (err) => {
        if (err) return next(err);
        const { password: _, ...safeUser } = user;
        res.json({ success: true, user: safeUser });
      });
    })(req, res, next);
  });

  // ── LOGOUT ──────────────────────────────────────────────
  app.post("/api/auth/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.json({ success: true });
      });
    });
  });

  // ── CURRENT USER ────────────────────────────────────────
  app.get("/api/auth/me", (req, res) => {
    if (!req.isAuthenticated() && !req.session?.userId) {
      return res.status(401).json({ user: null });
    }
    const user = req.user as any;
    if (!user) return res.status(401).json({ user: null });
    const { password: _, ...safeUser } = user;
    res.json({ user: safeUser });
  });

  // ── GOOGLE OAUTH ─────────────────────────────────────────
  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login?error=google" }),
    (req, res) => {
      res.redirect("/");
    }
  );

  // ── CHECK USERNAME AVAILABILITY ───────────────────────────
  app.get("/api/auth/check-username", async (req, res) => {
    const { username } = req.query;
    if (!username) return res.status(400).json({ error: "Username required" });
    const existing = await storage.getUserByUsername(username as string);
    res.json({ available: !existing });
  });
}
