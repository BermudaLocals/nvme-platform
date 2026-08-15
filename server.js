// ========================================
// 🔐 Google OAuth Authentication
// ========================================
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, result.rows[0]);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.APP_URL || 'https://nvme.live'}/api/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const avatar = profile.photos[0]?.value || null;
    
    // Check if user exists in NeonDB
    let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user = result.rows[0];

    if (!user) {
      // Create new user seamlessly
      const newUser = await pool.query(
        `INSERT INTO users (id, username, email, display_name, avatar, provider, provider_id, plan, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'free', NOW())
         RETURNING *`,
        [uuidv4(), email.split('@')[0], email, name, avatar, 'google', profile.id]
      );
      user = newUser.rows[0];
    }
    return done(null, user);
  }
));

app.use(passport.initialize());

// Route: Start Google OAuth flow
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Route: Google OAuth callback
app.get('/api/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Success! Generate a JWT for your frontend
    const token = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET);
    res.redirect(`/?token=${token}`);
  }
);

// Logout route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect('/');
  });
});
