/**
 * Serverless API Route: /api/enquiry
 * Handles Freelance Project Enquiries with server-side validation,
 * anti-spam honeypot, rate limiting, and email delivery via Resend (or SMTP).
 */

// Simple in-memory rate limiter for serverless instance (sliding window)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_REQUESTS_PER_WINDOW = 5;

function isRateLimited(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  if (!record) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  if (now > record.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  if (record.count >= MAX_REQUESTS_PER_WINDOW) {
    return true;
  }
  record.count += 1;
  return false;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

module.exports = async function handler(req, res) {
  // Set CORS and security headers
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method Not Allowed. Use POST.' });
  }

  try {
    const clientIp =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      'unknown';

    // 1. Rate limiting check
    if (isRateLimited(clientIp)) {
      return res.status(429).json({
        success: false,
        error: 'Too many requests. Please wait a few minutes before submitting another enquiry.'
      });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};

    // 2. Honeypot check (anti-spam bot trap)
    if (body._hp && String(body._hp).trim().length > 0) {
      console.warn(`[Anti-Spam] Honeypot triggered from IP: ${clientIp}`);
      // Return 200 without sending email so spam bots think it succeeded
      return res.status(200).json({
        success: true,
        message: 'Your project enquiry has been submitted successfully.'
      });
    }

    // 3. Server-side Field Validation & Sanitization
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const company = String(body.company || '').trim();
    const website = String(body.website || '').trim();
    const service = String(body.service || '').trim();
    const budget = String(body.budget || '').trim();
    const timeline = String(body.timeline || '').trim();
    const message = String(body.message || '').trim();

    if (!name || name.length < 2 || name.length > 100) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid Full Name (2 to 100 characters).'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    if (!email || !emailRegex.test(email) || email.length > 150) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid business email address.'
      });
    }

    const validServices = [
      'Technical SEO Audit',
      'Website Speed Optimization',
      'Website Development',
      'SEO & Content Marketing',
      'AEO / GEO Optimization',
      'Other'
    ];

    if (!service || !validServices.includes(service)) {
      return res.status(400).json({
        success: false,
        error: 'Please select a valid service from the dropdown.'
      });
    }

    if (!message || message.length < 10 || message.length > 5000) {
      return res.status(400).json({
        success: false,
        error: 'Please provide project details (minimum 10 characters, maximum 5000 characters).'
      });
    }

    if (website && !/^https?:\/\//i.test(website) && !/^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(website)) {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid website URL or domain (e.g. https://yourcompany.com).'
      });
    }

    // 4. Email Service Configuration
    const recipientEmail = process.env.TO_EMAIL || 'mmanikandan1322002@gmail.com';
    const fromEmail = process.env.FROM_EMAIL || 'Portfolio Enquiry <onboarding@resend.dev>';
    const resendApiKey = process.env.RESEND_API_KEY;

    // Check if email service credential is provided
    if (!resendApiKey) {
      console.warn('[Email Config] RESEND_API_KEY environment variable is missing.');
      return res.status(503).json({
        success: false,
        error:
          'Email backend is awaiting configuration. Please set RESEND_API_KEY in your Vercel Environment Variables.'
      });
    }

    // Support mock verification in local test environment
    if (resendApiKey === 'test_mock_key') {
      return res.status(200).json({
        success: true,
        message:
          'Thank you for reaching out! Your project enquiry has been submitted successfully. I’ll review your requirements and get back to you as soon as possible.',
        id: 'mock_resend_' + Date.now()
      });
    }

    // Build Email HTML Template
    const safeName = escapeHtml(name);
    const safeEmail = escapeHtml(email);
    const safeCompany = escapeHtml(company || 'Not specified');
    const safeWebsite = escapeHtml(website || 'Not specified');
    const safeService = escapeHtml(service);
    const safeBudget = escapeHtml(budget || 'Not specified');
    const safeTimeline = escapeHtml(timeline || 'Not specified');
    const safeMessage = escapeHtml(message).replace(/\n/g, '<br>');

    const emailSubject = `New Freelance Project Enquiry: ${safeName} (${safeService})`;

    const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #2D1810; background: #FAF5F0; margin: 0; padding: 24px; }
    .container { max-width: 600px; margin: 0 auto; background: #FFFFFF; border-radius: 12px; border: 1px solid #EAD8C8; overflow: hidden; box-shadow: 0 4px 14px rgba(0,0,0,0.06); }
    .header { background: #6C151E; color: #F5DABF; padding: 24px 28px; }
    .header h2 { margin: 0 0 6px; font-size: 22px; font-weight: 700; color: #F5DABF; }
    .header p { margin: 0; font-size: 14px; opacity: 0.9; color: #F5DABF; }
    .content { padding: 28px; }
    .item { margin-bottom: 18px; padding-bottom: 14px; border-bottom: 1px solid #F0E4D8; }
    .item:last-child { border-bottom: none; }
    .label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #8A4E38; margin-bottom: 4px; }
    .value { font-size: 15px; color: #1A0F0D; font-weight: 500; }
    .value a { color: #6C151E; text-decoration: none; font-weight: 600; }
    .message-box { background: #FBF7F3; border-left: 4px solid #6C151E; padding: 14px 18px; border-radius: 4px; font-size: 14.5px; line-height: 1.6; color: #2A1914; }
    .footer { background: #F5EDE4; padding: 16px 28px; font-size: 12px; color: #7A5B4C; text-align: center; border-top: 1px solid #EAD8C8; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2>New Project Enquiry</h2>
      <p>Submitted via Manikandan M Portfolio website</p>
    </div>
    <div class="content">
      <div class="item">
        <div class="label">Client Name</div>
        <div class="value">${safeName}</div>
      </div>
      <div class="item">
        <div class="label">Business Email</div>
        <div class="value"><a href="mailto:${safeEmail}">${safeEmail}</a></div>
      </div>
      <div class="item">
        <div class="label">Company / Organization</div>
        <div class="value">${safeCompany}</div>
      </div>
      <div class="item">
        <div class="label">Website URL</div>
        <div class="value">${website ? `<a href="${safeWebsite.startsWith('http') ? safeWebsite : 'https://' + safeWebsite}" target="_blank">${safeWebsite}</a>` : 'Not specified'}</div>
      </div>
      <div class="item">
        <div class="label">Service Required</div>
        <div class="value"><strong style="color:#6C151E;">${safeService}</strong></div>
      </div>
      <div class="item">
        <div class="label">Budget Range</div>
        <div class="value">${safeBudget}</div>
      </div>
      <div class="item">
        <div class="label">Project Timeline</div>
        <div class="value">${safeTimeline}</div>
      </div>
      <div class="item">
        <div class="label">Project Details / Message</div>
        <div class="message-box">${safeMessage}</div>
      </div>
    </div>
    <div class="footer">
      Received from IP: ${escapeHtml(clientIp)} &bull; ${new Date().toISOString()}
    </div>
  </div>
</body>
</html>
    `;

    // 5. Send via Resend REST API
    const resendResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [recipientEmail],
        reply_to: email,
        subject: emailSubject,
        html: emailHtml
      })
    });

    const resendData = await resendResponse.json();

    if (!resendResponse.ok) {
      console.error('[Resend Error]', resendData);
      return res.status(502).json({
        success: false,
        error: resendData.message || 'Failed to deliver email through email service. Please try again or reach out directly.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Thank you for reaching out! Your project enquiry has been submitted successfully. I’ll review your requirements and get back to you as soon as possible.',
      id: resendData.id
    });

  } catch (err) {
    console.error('[Handler Error]', err);
    return res.status(500).json({
      success: false,
      error: 'An unexpected error occurred while processing your request. Please try again later.'
    });
  }
};
