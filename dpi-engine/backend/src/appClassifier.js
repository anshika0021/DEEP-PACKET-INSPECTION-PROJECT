/**
 * Application Classifier
 * Maps domain names to known applications
 */

const APP_SIGNATURES = [
  // Streaming
  { app: 'YouTube',    patterns: ['youtube.com', 'ytimg.com', 'googlevideo.com', 'youtu.be'] },
  { app: 'Netflix',    patterns: ['netflix.com', 'nflximg.net', 'nflxvideo.net', 'nflxso.net'] },
  { app: 'Twitch',     patterns: ['twitch.tv', 'twitchapps.com', 'jtvnw.net'] },
  { app: 'Disney+',    patterns: ['disneyplus.com', 'disney-plus.net', 'bamgrid.com'] },
  { app: 'Spotify',    patterns: ['spotify.com', 'scdn.co', 'spotifycdn.com'] },
  { app: 'TikTok',     patterns: ['tiktok.com', 'tiktokcdn.com', 'muscdn.com', 'musical.ly'] },
  // Social
  { app: 'Facebook',   patterns: ['facebook.com', 'fbcdn.net', 'fb.com', 'instagram.com'] },
  { app: 'Twitter/X',  patterns: ['twitter.com', 'twimg.com', 't.co', 'abs.twimg.com'] },
  { app: 'LinkedIn',   patterns: ['linkedin.com', 'licdn.com'] },
  { app: 'Reddit',     patterns: ['reddit.com', 'redd.it', 'redditmedia.com'] },
  { app: 'WhatsApp',   patterns: ['whatsapp.com', 'whatsapp.net'] },
  { app: 'Telegram',   patterns: ['telegram.org', 't.me'] },
  // Google
  { app: 'Google',     patterns: ['google.com', 'googleapis.com', 'gstatic.com', 'ggpht.com'] },
  { app: 'Gmail',      patterns: ['mail.google.com', 'smtp.gmail.com'] },
  { app: 'Google Drive',patterns: ['drive.google.com'] },
  { app: 'Google Meet',patterns: ['meet.google.com'] },
  // Microsoft
  { app: 'Microsoft',  patterns: ['microsoft.com', 'live.com', 'msn.com', 'bing.com'] },
  { app: 'Teams',      patterns: ['teams.microsoft.com', 'teams.live.com', 'skype.com', 'teams.cdn.office.net'] },
  { app: 'OneDrive',   patterns: ['onedrive.live.com', 'sharepoint.com'] },
  // Dev
  { app: 'GitHub',     patterns: ['github.com', 'githubusercontent.com', 'githubassets.com'] },
  { app: 'Cloudflare', patterns: ['cloudflare.com', 'cloudflareinsights.com', '1.1.1.1'] },
  { app: 'AWS',        patterns: ['amazonaws.com', 'aws.amazon.com', 'cloudfront.net'] },
  // Commerce
  { app: 'Amazon',     patterns: ['amazon.com', 'amazon.in', 'amazon.co', 'ssl-images-amazon.com'] },
  { app: 'Zoom',       patterns: ['zoom.us', 'zoomgov.com'] },
  { app: 'Slack',      patterns: ['slack.com', 'slack-edge.com'] },
];

/**
 * Classify an SNI or HTTP Host header to an app name
 * @param {string} host - the domain/SNI
 * @returns {{ app: string, category: string }}
 */
function classifyHost(host) {
  if (!host) return { app: 'Unknown', category: 'unknown' };

  const lower = host.toLowerCase().replace(/:\d+$/, '');

  for (const sig of APP_SIGNATURES) {
    for (const pattern of sig.patterns) {
      // Exact match OR subdomain (.youtube.com matches s.youtube.com)
      if (lower === pattern || lower.endsWith('.' + pattern)) {
        return { app: sig.app, category: getCategory(sig.app) };
      }
    }
  }

  return { app: 'Unknown', category: 'unknown' };
}

function getCategory(app) {
  const streaming = ['YouTube', 'Netflix', 'Twitch', 'Disney+', 'Spotify', 'TikTok'];
  const social = ['Facebook', 'Twitter/X', 'LinkedIn', 'Reddit', 'WhatsApp', 'Telegram'];
  const google = ['Google', 'Gmail', 'Google Drive', 'Google Meet'];
  const microsoft = ['Microsoft', 'Teams', 'OneDrive'];
  const dev = ['GitHub', 'Cloudflare', 'AWS'];

  if (streaming.includes(app)) return 'streaming';
  if (social.includes(app)) return 'social';
  if (google.includes(app)) return 'google';
  if (microsoft.includes(app)) return 'microsoft';
  if (dev.includes(app)) return 'developer';
  return 'other';
}

module.exports = { classifyHost, APP_SIGNATURES };
