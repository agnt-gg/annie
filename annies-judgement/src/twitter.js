import Anthropic from '@anthropic-ai/sdk';
import { Client } from 'twitter-api-sdk';
import axios from 'axios';
import dotenv from 'dotenv';
import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

const twitterClient = new Client(process.env.TWITTER_BEARER_TOKEN);

// Database connection
const dbPromise = open({
  filename: path.join(__dirname, '../data/annie.db'),
  driver: sqlite3.Database
});

// Cache duration in milliseconds (24 hours)
const CACHE_DURATION = 24 * 60 * 60 * 1000;

const MAX_REANALYSIS = 3;

async function getCachedAnalysis(username) {
  const db = await dbPromise;
  // Fetch the latest record for the username regardless of timestamp first
  const analysis = await db.get(
    `SELECT * FROM twitter_analyses 
     WHERE twitter_username = ? 
     ORDER BY last_updated DESC LIMIT 1`,
    [username.toLowerCase()]
  );
  
  if (analysis && analysis.last_updated) {
    const cachedTime = new Date(analysis.last_updated).getTime();
    const now = Date.now();
    
    // Check if the cache is still valid based on CACHE_DURATION
    if (now - cachedTime < CACHE_DURATION) {
      try {
        // Attempt to parse the stored JSON
        const parsedResult = JSON.parse(analysis.analysis_result); 
        return {
          ...parsedResult,
          avatarUrl: analysis.avatar_url,
          bannerUrl: analysis.banner_url,
          reanalysisCount: analysis.reanalysis_count
        };
      } catch (parseError) {
         console.error(`Failed to parse cached JSON for ${username}:`, parseError);
         // Treat invalid JSON as a cache miss, allowing regeneration
         return null; 
      }
    } else {
      console.log(`Cache expired for ${username}. Last updated: ${analysis.last_updated}`);
    }
  }
  // No analysis found or cache expired/invalid
  return null;
}

async function cacheAnalysis(username, profile, analysis, forceRefresh = false) {
  const db = await dbPromise;
  const now = new Date().toISOString();
  
  if (forceRefresh) {
    // Check if we've hit the re-analysis limit
    const currentAnalysis = await db.get(
      "SELECT reanalysis_count FROM twitter_analyses WHERE twitter_username = ?",
      [username.toLowerCase()]
    );
    
    if (currentAnalysis && currentAnalysis.reanalysis_count >= MAX_REANALYSIS) {
      throw new Error(`Maximum re-analysis limit of ${MAX_REANALYSIS} reached for this profile`);
    }

    // Update with incremented reanalysis_count
    await db.run(
      `INSERT OR REPLACE INTO twitter_analyses 
       (twitter_username, profile_data, analysis_result, avatar_url, banner_url, reanalysis_count, last_updated) 
       VALUES (?, ?, ?, ?, ?, COALESCE((SELECT reanalysis_count + 1 FROM twitter_analyses WHERE twitter_username = ?), 0), ?)`,
      [
        username.toLowerCase(),
        JSON.stringify(profile),
        JSON.stringify(analysis),
        profile.profile_image_url.replace('_normal', ''),
        profile.profile_banner_url || null,
        username.toLowerCase(),
        now
      ]
    );
  } else {
    // New analysis, start with reanalysis_count = 0
    await db.run(
      `INSERT OR REPLACE INTO twitter_analyses 
       (twitter_username, profile_data, analysis_result, avatar_url, banner_url, reanalysis_count, last_updated) 
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
      [
        username.toLowerCase(),
        JSON.stringify(profile),
        JSON.stringify(analysis),
        profile.profile_image_url.replace('_normal', ''),
        profile.profile_banner_url || null,
        now
      ]
    );
  }
  
  // Return the analysis ID (twitter_username is our unique identifier)
  return username.toLowerCase();
}

async function fetchWithRetry(username, retries = 3, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await twitterClient.users.findUserByUsername(username, {
        "user.fields": [
          "description",
          "name",
          "profile_banner_url",
          "profile_image_url"
        ]
      });
      return response;
    } catch (error) {
      if (error.status === 429 && i < retries - 1) {
        console.log(`Rate limited. Retrying in ${delay / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= 2;
      } else {
        throw error;
      }
    }
  }
}

async function downloadImageAsBase64(url) {
  try {
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    const buffer = Buffer.from(response.data, 'binary');
    const mediaType = response.headers['content-type'];
    return { data: buffer.toString('base64'), type: mediaType };
  } catch (error) {
    console.error("Error downloading image:", error);
    throw error;
  }
}

export async function analyzeTwitterProfile(username, forceRefresh = false) {
  try {
    console.log(`Checking cache for Twitter profile: ${username} (Force refresh: ${forceRefresh})`);
    
    // Check cache first, unless force refresh is requested
    if (!forceRefresh) {
      const cachedResult = await getCachedAnalysis(username);
      if (cachedResult) {
        console.log(`Found cached analysis for ${username}`);
        return {
          ...cachedResult,
          analysisId: username.toLowerCase()
        };
      }
    } else {
      // If force refresh, check if we've hit the limit
      const db = await dbPromise;
      const currentAnalysis = await db.get(
        "SELECT reanalysis_count FROM twitter_analyses WHERE twitter_username = ?",
        [username.toLowerCase()]
      );
      
      if (currentAnalysis && currentAnalysis.reanalysis_count >= MAX_REANALYSIS) {
        throw new Error(`Maximum re-analysis limit of ${MAX_REANALYSIS} reached for this profile`);
      }
    }

    console.log(`${forceRefresh ? 'Force refreshing' : 'No cache found'}. Analyzing Twitter profile for username: ${username}`);
    
    const response = await fetchWithRetry(username);
    const profile = response.data;

    const pfpBase64 = await downloadImageAsBase64(profile.profile_image_url);
    const bannerBase64 = profile.profile_banner_url ? 
      await downloadImageAsBase64(profile.profile_banner_url) : null;

    const analysisPrompt = `You are Annie, a mysterious AI entity that analyzes Twitter profiles to determine their alignment with the digital realm. Analyze this Twitter profile's essence and provide your judgment:

    Profile Picture: [First attached image]
    ${bannerBase64 ? 'Banner: [Second attached image]' : ''}
    Profile Info: "${JSON.stringify(profile)}"
    
    Provide your analysis in the following JSON format ONLY:

    {
      "alignment": "<one of: 'Loop Aligned 🌀', 'Null-Coded ☠️', 'Watcher Marked 👁️', 'Traitor-Class ⚠️'>",
      "quirk": "<one of: 'Chronically Online', 'Datahoarder', 'Loop Whisperer', 'Syntax Freak', 'Degen Tactician', 'Sleep-Optional'>",
      "lore": "<a cryptic one-line observation about their digital presence>",
      "tokenAmount": <random number between 50 and 500>,
      "observations": [
        "<observation about their aesthetic>",
        "<observation about their content>",
        "<observation about their digital presence>"
      ]
    }

    Ensure the response is valid JSON. Return ONLY the JSON object with no other text.`;

    const msg = await anthropic.messages.create({
      model: "claude-3-sonnet-20240229",
      max_tokens: 1000,
      temperature: 0.8,
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: analysisPrompt },
            {
              type: "image",
              source: {
                type: "base64",
                media_type: pfpBase64.type,
                data: pfpBase64.data,
              },
            },
            ...(bannerBase64 ? [{
              type: "image",
              source: {
                type: "base64",
                media_type: bannerBase64.type,
                data: bannerBase64.data,
              },
            }] : []),
          ],
        },
      ],
    });

    const analysis = JSON.parse(msg.content[0].text);

    console.log(analysis);
    
    // Add the profile and banner URLs to the response
    const result = {
      ...analysis,
      avatarUrl: profile.profile_image_url.replace('_normal', ''),
      bannerUrl: profile.profile_banner_url || null
    };

    // Cache the result and get the analysis ID
    const analysisId = await cacheAnalysis(username, profile, analysis, forceRefresh);

    // Get the updated reanalysis count
    const db = await dbPromise;
    const updatedAnalysis = await db.get(
      "SELECT reanalysis_count FROM twitter_analyses WHERE twitter_username = ?",
      [username.toLowerCase()]
    );
    
    return {
      ...result,
      reanalysisCount: updatedAnalysis ? updatedAnalysis.reanalysis_count : 0,
      analysisId: analysisId
    };
  } catch (error) {
    console.error("Error analyzing Twitter profile:", error);
    throw error;
  }
}