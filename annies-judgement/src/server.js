import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { setupAuth, generateTemporaryReferralCode } from './auth.js';
import session from 'express-session';
import dotenv from 'dotenv';
import { analyzeTwitterProfile } from './twitter.js';
import { uploadToImgur } from './imgur.js';
import axios from 'axios';
import passport from 'passport';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 7777;

// Increase payload size limit (add these lines before other middleware)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Session configuration - this needs to be BEFORE auth routes
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-annie-audit',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['annie.agnt.gg', 'your-production-domain.com']
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

app.use(express.json());

// Debug middleware to log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url} SessionID: ${req.sessionID}`);
  console.log("Session Data:", req.session);
  next();
});

// Setup auth BEFORE static file serving and catch-all route
await setupAuth(app);

// Serve static files AFTER auth routes but BEFORE catch-all
app.use(express.static(path.join(__dirname, '../public')));

// Add this route before the catch-all route
app.post('/api/analyze-twitter', async (req, res) => {
  try {
    const { username, forceRefresh } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    const analysis = await analyzeTwitterProfile(username, forceRefresh);
    
    // Store the tokenAmount and analysisId in the session
    req.session.analysisId = analysis.analysisId;
    req.session.tokenAmount = analysis.tokenAmount;
    console.log(`Stored in session - Analysis ID: ${analysis.analysisId}, Token Amount: ${analysis.tokenAmount}`);
    
    // Only generate a temporary referral code if user is not logged in AND no referral code exists
    if (!req.user && !req.session.pendingReferral && !req.session.tempReferralCode) {
      const tempRefCode = generateTemporaryReferralCode(username);
      req.session.tempReferralCode = tempRefCode;
      analysis.tempReferralCode = tempRefCode;
    } else if (!req.user) {
      // Use existing referral code (either pending or temporary)
      analysis.tempReferralCode = req.session.pendingReferral || req.session.tempReferralCode;
    }
    
    res.json(analysis);
  } catch (error) {
    console.error('Twitter analysis error:', error);
    if (error.message.includes('Maximum re-analysis limit')) {
      res.status(429).json({ error: error.message });
    } else if (error.message.includes('Twitter profile not found')) {
      res.status(404).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to analyze Twitter profile' });
    }
  }
});

// Add this route before the catch-all route
app.post('/api/share', async (req, res) => {
  try {
    const { image, auditData } = req.body;
    if (!image || !auditData) {
      return res.status(400).json({ error: 'Image data and audit data are required.' });
    }

    // Upload image to Imgur
    const imageUrl = await uploadToImgur(image);
    
    // Encode data including the direct image URL
    const sharePayload = {
      i: imageUrl,
      d: auditData
    };

    // Create a unique share ID (base64 encoding of the payload)
    const shareId = Buffer.from(JSON.stringify(sharePayload)).toString('base64url');
    
    res.json({
      shareUrl: `${process.env.APP_URL}?share=${shareId}`,
      imageUrl: imageUrl
    });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: error.message || 'Failed to create share link' });
  }
});

// Add this route to handle share links
app.get('/api/share/:id', async (req, res) => {
  try {
    const shareData = JSON.parse(Buffer.from(req.params.id, 'base64url').toString());
    res.json(shareData);
  } catch (error) {
    res.status(404).json({ error: 'Share not found or invalid' });
  }
});

// Add proxy endpoint for Twitter images
app.get('/proxy-image', async (req, res) => {
  try {
    const imageUrl = req.query.url;
    if (!imageUrl) {
      return res.status(400).send('No image URL provided');
    }

    const parsedUrl = new URL(imageUrl);
    if (!['https:', 'http:'].includes(parsedUrl.protocol)) {
      return res.status(400).send('Invalid URL protocol');
    }

    const response = await axios({
      url: imageUrl,
      responseType: 'arraybuffer',
      timeout: 10000
    });

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
    
    res.send(response.data);
  } catch (error) {
    console.error('Error proxying image:', error.message);
    if (error.response) {
      res.status(error.response.status).send('Error fetching image from source');
    } else if (error.request) {
      res.status(504).send('Timeout or connection error fetching image');
    } else {
      res.status(500).send('Error processing image proxy request');
    }
  }
});

// Add Google authentication route
app.get('/auth/google', (req, res, next) => {
  console.log('Google auth route hit');
  const pendingReferral = req.query.ref;
  if (pendingReferral) {
      req.session.pendingReferral = pendingReferral;
      console.log("Stored pending referral in session:", pendingReferral);
  }

  // The token amount is now stored securely when the analysis is performed
  // We no longer need to get it from query params
  
  passport.authenticate('google', {
    scope: ['profile', 'email']
  })(req, res, next);
});

// Catch-all route should be LAST and should NOT handle /auth/* routes
app.get('*', (req, res, next) => {
  if (req.url.startsWith('/auth/')) {
    return next(); // Pass auth routes through
  }
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(port, () => {
  console.log('----------------------------------------');
  console.log(`Server running at http://localhost:${port}`);
  console.log('Environment:', process.env.NODE_ENV);
  console.log('Auth Configuration:');
  console.log('- Session Secret exists:', !!process.env.SESSION_SECRET);
  console.log('- JWT Secret exists:', !!process.env.JWT_SECRET);
  console.log('Google OAuth Configuration:');
  console.log('- Client ID exists:', !!process.env.GOOGLE_CLIENT_ID);
  console.log('- Client Secret exists:', !!process.env.GOOGLE_CLIENT_SECRET);
  console.log('- Callback URL:', '/auth/google/callback');
  console.log('----------------------------------------');
});