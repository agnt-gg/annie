import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import session from 'express-session';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { uniqueNamesGenerator, adjectives, colors, animals } from 'unique-names-generator';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createHash } from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Constants
const INITIAL_BALANCE = 0; // Default to 0, will use token amount from analysis
const REFERRAL_BONUS = 100;
const REFERRED_BONUS = 50;

// Database setup
const dbPromise = open({
  filename: path.join(__dirname, '../data/annie.db'),
  driver: sqlite3.Database
});

async function initDb() {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      referral_code TEXT UNIQUE NOT NULL,
      balance INTEGER DEFAULT 0,
      google_id TEXT UNIQUE,
      referred_by_user_id INTEGER,
      pseudonym TEXT UNIQUE NOT NULL,
      referral_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS twitter_analyses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      twitter_username TEXT UNIQUE,
      profile_data TEXT,
      analysis_result TEXT,
      avatar_url TEXT,
      banner_url TEXT,
      reanalysis_count INTEGER DEFAULT 0,
      last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_twitter_username ON twitter_analyses(twitter_username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
  `);
}

async function generateUniquePseudonym(db) {
  while (true) {
    const pseudonym = uniqueNamesGenerator({
      dictionaries: [adjectives, colors, animals],
      length: 3,
      separator: '',
      style: 'capital'
    });
    const existing = await db.get("SELECT * FROM users WHERE pseudonym = ?", [pseudonym]);
    if (!existing) {
      return pseudonym;
    }
  }
}

function generateUniqueReferralCode(email, db, attempt = 0) {
  const hash = createHash('sha256').update(email.toLowerCase() + (attempt ? attempt.toString() : '')).digest('hex');
  return BigInt('0x' + hash).toString(36).slice(0, 8).toUpperCase();
}

async function ensureUniqueReferralCode(email, db, tempCode = null) {
  let attempt = 0;
  let referralCode = tempCode ? tempCode.replace(/^T/, '') : generateUniqueReferralCode(email, db);
  
  while (attempt < 10) {
    const existing = await db.get("SELECT id FROM users WHERE referral_code = ?", [referralCode]);
    if (!existing) {
      return referralCode;
    }
    attempt++;
    referralCode = generateUniqueReferralCode(email, db, attempt);
  }
  throw new Error("Failed to generate unique referral code after 10 attempts");
}

// Add new function for temporary referral codes
function generateTemporaryReferralCode(uniqueId) {
  const hash = createHash('sha256').update('temp_' + uniqueId.toLowerCase()).digest('hex');
  return 'T' + BigInt('0x' + hash).toString(36).slice(0, 7).toUpperCase();
}

// Export the function
export { generateTemporaryReferralCode };

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Authentication required' });
}

export async function setupAuth(app) {
  await initDb();
  const db = await dbPromise;

  // Initialize passport
  app.use(passport.initialize());
  app.use(passport.session());

  // Set up Google Strategy
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.APP_URL}/auth/google/callback`,
    proxy: true,
    passReqToCallback: true
  }, async (req, accessToken, refreshToken, profile, cb) => {
    try {
      console.log("Google auth callback received for profile:", profile.id);
      
      const email = profile.emails[0].value;
      let user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
      const pendingReferralCode = req.session.pendingReferral || req.session.tempReferralCode;
      console.log("Pending referral code from session:", pendingReferralCode);

      // Add additional logging for analysis ID and token amount
      console.log("Analysis ID from session:", req.session.analysisId);
      console.log("Token Amount from session:", req.session.tokenAmount);

      if (!user) {
        console.log("Creating new user for:", email);
        // Generate a unique referral code, trying to use the temp code first if available
        const referralCode = await ensureUniqueReferralCode(email, db, pendingReferralCode);
        console.log("Generated unique referral code:", referralCode);
        
        const pseudonym = await generateUniquePseudonym(db);
        
        // Start with zero balance, will update with token amount from analysis
        let initialBalance = INITIAL_BALANCE;

        // First prioritize getting token amount from the database using analysis ID
        if (req.session.analysisId) {
          try {
            const analysisRecord = await db.get(
              "SELECT analysis_result FROM twitter_analyses WHERE twitter_username = ?",
              [req.session.analysisId]
            );
            
            if (analysisRecord && analysisRecord.analysis_result) {
              const analysisData = JSON.parse(analysisRecord.analysis_result);
              if (analysisData && analysisData.tokenAmount) {
                initialBalance = analysisData.tokenAmount;
                console.log(`Setting initial balance to ${initialBalance} tokens from database analysis record`);
              }
            }
          } catch (dbError) {
            console.error("Error retrieving analysis from database:", dbError);
            // Fall back to session token amount if available
            if (req.session.tokenAmount) {
              const analysisTokens = parseInt(req.session.tokenAmount, 10);
              if (!isNaN(analysisTokens)) {
                initialBalance = analysisTokens;
                console.log(`Falling back to session token amount: ${initialBalance}`);
              }
            }
          }
        } 
        // If no analysis ID, use session token amount as fallback
        else if (req.session.tokenAmount) {
          const analysisTokens = parseInt(req.session.tokenAmount, 10);
          if (!isNaN(analysisTokens)) {
            initialBalance = analysisTokens;
            console.log(`Setting initial balance to ${initialBalance} tokens from session`);
          }
        }

        let referredByUserId = null;

        if (pendingReferralCode) {
            // First try to find a user with this referral code
            let referrer = await db.get(
              "SELECT * FROM users WHERE referral_code = ?",
              [pendingReferralCode]
            );

            // If not found and it's a T-prefixed code, try to find the code without the T
            if (!referrer && pendingReferralCode.startsWith('T')) {
              referrer = await db.get(
                "SELECT * FROM users WHERE referral_code = ?",
                [pendingReferralCode.substring(1)]
              );
            }

            if (referrer && referrer.email !== email) {
                console.log(`User referred by ${referrer.email} (ID: ${referrer.id})`);
                initialBalance += REFERRED_BONUS; // Add referral bonus to the analysis token amount
                referredByUserId = referrer.id;
                
                // Start transaction for updating referrer's balance
                await db.run('BEGIN TRANSACTION');
                try {
                    await db.run(
                      "UPDATE users SET balance = balance + ?, referral_count = referral_count + 1 WHERE id = ?",
                      [REFERRAL_BONUS, referrer.id]
                    );
                    console.log(`Awarded ${REFERRAL_BONUS} points to referrer ID: ${referrer.id}`);
                    await db.run('COMMIT');
                } catch (error) {
                    await db.run('ROLLBACK');
                    console.error("Failed to update referrer balance:", error);
                    throw error;
                }
            } else {
                console.log("Invalid or self-referral code detected.");
            }
        }

        // Start transaction for new user creation
        await db.run('BEGIN TRANSACTION');
        try {
            await db.run(
              "INSERT INTO users (email, referral_code, google_id, pseudonym, balance, referred_by_user_id) VALUES (?, ?, ?, ?, ?, ?)",
              [email, referralCode, profile.id, pseudonym, initialBalance, referredByUserId]
            );
            
            user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
            console.log("New user created with balance:", initialBalance);
            
            await db.run('COMMIT');
        } catch (error) {
            await db.run('ROLLBACK');
            console.error("Failed to create new user:", error);
            throw error;
        }
      }
      // For existing users, check if we need to update their balance based on a new analysis
      else if (req.session.analysisId) {
        try {
          // First try to get token amount from the database record
          const analysisRecord = await db.get(
            "SELECT analysis_result FROM twitter_analyses WHERE twitter_username = ?",
            [req.session.analysisId]
          );
          
          if (analysisRecord && analysisRecord.analysis_result) {
            const analysisData = JSON.parse(analysisRecord.analysis_result);
            if (analysisData && analysisData.tokenAmount) {
              const analysisTokens = analysisData.tokenAmount;
              console.log(`Found token amount in database: ${analysisTokens}`);
              
              // Update the user's balance with the analysis token amount if higher than current balance
              if (analysisTokens > user.balance) {
                await db.run(
                  "UPDATE users SET balance = ? WHERE id = ?",
                  [analysisTokens, user.id]
                );
                user = await db.get("SELECT * FROM users WHERE id = ?", [user.id]);
                console.log(`Updated user balance to: ${user.balance} from database analysis`);
              }
            }
          }
        } catch (dbError) {
          console.error("Error retrieving analysis from database:", dbError);
          // Fall back to session token amount if available
          if (req.session.tokenAmount) {
            const analysisTokens = parseInt(req.session.tokenAmount, 10);
            if (!isNaN(analysisTokens) && analysisTokens > user.balance) {
              await db.run(
                "UPDATE users SET balance = ? WHERE id = ?",
                [analysisTokens, user.id]
              );
              user = await db.get("SELECT * FROM users WHERE id = ?", [user.id]);
              console.log(`Updated user balance to: ${user.balance} from session fallback`);
            }
          }
        }
      }
      // If no analysis ID, fall back to session token amount
      else if (req.session.tokenAmount) {
        const analysisTokens = parseInt(req.session.tokenAmount, 10);
        if (!isNaN(analysisTokens)) {
          console.log(`Using session token amount: ${analysisTokens}`);
          
          // Update the user's balance with the analysis token amount if higher than current balance
          if (analysisTokens > user.balance) {
            await db.run(
              "UPDATE users SET balance = ? WHERE id = ?",
              [analysisTokens, user.id]
            );
            user = await db.get("SELECT * FROM users WHERE id = ?", [user.id]);
            console.log(`Updated user balance to: ${user.balance} from session`);
          }
        }
      }

      // Clean up session
      delete req.session.pendingReferral;
      delete req.session.tempReferralCode;
      delete req.session.tokenAmount;

      return cb(null, user);
    } catch (error) {
      console.error("Error in Google auth callback:", error);
      return cb(error);
    }
  }));

  // Serialize/Deserialize
  passport.serializeUser((user, done) => {
    console.log('Serializing user:', user.id);
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      console.log('Deserializing user:', id);
      const user = await db.get("SELECT id, email, referral_code, balance, pseudonym, referral_count FROM users WHERE id = ?", [id]);
      done(null, user);
    } catch (error) {
      console.error('Deserialize error:', error);
      done(error);
    }
  });

  // Auth Routes
  app.get('/auth/google', (req, res, next) => {
    console.log('Google auth route hit');
    const pendingReferral = req.query.ref;
    if (pendingReferral) {
        req.session.pendingReferral = pendingReferral;
        console.log("Stored pending referral in session:", pendingReferral);
    }
    
    // Also store token amount if present
    const tokenAmount = req.query.tokens;
    if (tokenAmount) {
        req.session.tokenAmount = tokenAmount;
        console.log("Stored token amount in session:", tokenAmount);
    }
    
    passport.authenticate('google', {
      scope: ['profile', 'email']
    })(req, res, next);
  });

  app.get('/auth/google/callback',
    (req, res, next) => {
      console.log('Google callback route hit');
      passport.authenticate('google', {
        failureRedirect: '/?authError=true'
      })(req, res, next);
    },
    (req, res) => {
      console.log('Google auth callback successful for user:', req.user?.email);
      const token = jwt.sign(
        {
          id: req.user.id,
          email: req.user.email,
          referralCode: req.user.referral_code,
          pseudonym: req.user.pseudonym,
          balance: req.user.balance,
          referralCount: req.user.referral_count
        },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );
      res.redirect(`/?token=${token}`);
    }
  );

  // Endpoint to get current user's info
  app.get('/api/user-info', requireAuth, (req, res) => {
      if (req.user) {
          res.json({
              success: true,
              user: {
                  pseudonym: req.user.pseudonym,
                  email: req.user.email,
                  balance: req.user.balance,
                  referralCode: req.user.referral_code,
                  referralCount: req.user.referral_count || 0
              }
          });
      } else {
          res.status(404).json({ success: false, message: 'User not found in session' });
      }
  });

  // Test endpoint
  app.get('/auth/test', (req, res) => {
    res.json({
      message: 'Auth routes working',
      user: req.user,
      session: req.session
    });
  });

  // API Routes
  app.get('/api/leaderboard', async (req, res) => {
    try {
      const leaderboard = await db.all(
        "SELECT pseudonym, balance, referral_count FROM users ORDER BY balance DESC LIMIT 10"
      );
      res.json(leaderboard);
    } catch (error) {
      console.error("Leaderboard error:", error);
      res.status(500).json({ error: "Failed to fetch leaderboard" });
    }
  });

  // --- Add New API Route for Pseudonym Update ---
  app.post('/api/update-pseudonym', requireAuth, async (req, res) => {
    const { newPseudonym } = req.body;
    const userId = req.user.id; // Get user ID from authenticated session

    if (!newPseudonym || typeof newPseudonym !== 'string') {
        return res.status(400).json({ success: false, message: "Invalid pseudonym provided." });
    }

    const trimmedPseudonym = newPseudonym.trim().slice(0, 32); // Trim whitespace and limit length

    if (trimmedPseudonym.length < 3) {
         return res.status(400).json({ success: false, message: "Pseudonym must be at least 3 characters long." });
    }

    // Basic validation: Allow letters, numbers, underscores, hyphens
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedPseudonym)) {
         return res.status(400).json({ success: false, message: "Pseudonym can only contain letters, numbers, underscores, and hyphens." });
    }

    const db = await dbPromise;
    try {
      // Check if the new pseudonym is already taken by another user
      const existingUser = await db.get(
          "SELECT id FROM users WHERE pseudonym = ? AND id != ?",
          [trimmedPseudonym, userId]
      );

      if (existingUser) {
        return res.status(409).json({ success: false, message: "This pseudonym is already taken." }); // 409 Conflict
      }

      // Update the pseudonym in the database
      await db.run("UPDATE users SET pseudonym = ? WHERE id = ?", [trimmedPseudonym, userId]);

      // Fetch the updated user data to include in the new token
       const updatedUser = await db.get("SELECT id, email, referral_code, balance, pseudonym, referral_count FROM users WHERE id = ?", [userId]);

      // Generate a new token with the updated pseudonym
      const newToken = jwt.sign(
        {
          id: updatedUser.id,
          email: updatedUser.email,
          referralCode: updatedUser.referral_code,
          pseudonym: updatedUser.pseudonym, // Use the new pseudonym
          balance: updatedUser.balance,
          referralCount: updatedUser.referral_count
        },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );

      console.log(`User ID ${userId} updated pseudonym to ${trimmedPseudonym}`);
      res.json({
          success: true,
          message: "Pseudonym updated successfully.",
          newToken: newToken, // Send the new token back to the client
          newPseudonym: trimmedPseudonym // Send back the finalized pseudonym
      });

    } catch (error) {
      console.error("Error updating pseudonym for user ID", userId, ":", error);
      res.status(500).json({ success: false, message: "An internal error occurred while updating the pseudonym." });
    }
  });
}