'use strict';

const express = require('express');
const https   = require('https');
const cors    = require('cors');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 8080;

const AUTH_TOKEN = process.env.STREAM_AUTH_TOKEN;
if (!AUTH_TOKEN) {
    console.error('[CloudVault] FATAL: STREAM_AUTH_TOKEN is not set.');
    process.exit(1);
}

// ── Active stream tracking ────────────────────────────────────────────────────
let activeStreams = 0;
let totalServed  = 0;

app.use(cors({
    origin: '*',
    methods: ['GET', 'HEAD', 'OPTIONS'],
    allowedHeaders: ['Range'],
    exposedHeaders: ['Content-Range', 'Content-Length', 'Accept-Ranges', 'Content-Type'],
}));

// ── HMAC verification ─────────────────────────────────────────────────────────
function verifyToken(fileId, token, expires) {
    if (!token || !expires) return false;

    const expiresAt = parseInt(expires, 10);
    if (isNaN(expiresAt) || Math.floor(Date.now() / 1000) > expiresAt) {
        return false;
    }

    const expected = crypto
        .createHmac('sha256', AUTH_TOKEN)
        .update(`${fileId}:${expires}`)
        .digest('hex');

    try {
        return crypto.timingSafeEqual(
            Buffer.from(token,    'hex'),
            Buffer.from(expected, 'hex'),
        );
    } catch {
        return false;
    }
}

// ── Health endpoint ───────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
    const mem = process.memoryUsage();
    res.json({
        status:        'ok',
        uptime:        Math.floor(process.uptime()),
        activeStreams,
        totalServed,
        memoryMB: {
            rss:      Math.round(mem.rss       / 1048576),
            heapUsed: Math.round(mem.heapUsed  / 1048576),
            heapTotal:Math.round(mem.heapTotal / 1048576),
        },
    });
});

// ── Stream endpoint ───────────────────────────────────────────────────────────
app.get('/stream/:fileId', (req, res) => {
    const { fileId }              = req.params;
    const { token, expires, at }  = req.query;
    const reqId = `${fileId.slice(0, 8)}-${Date.now() % 100000}`;

    // ── Auth checks ───────────────────────────────────────────────────────────
    if (!verifyToken(fileId, token, expires)) {
        const now = Math.floor(Date.now() / 1000);
        const exp = parseInt(expires, 10) || 0;
        console.warn(`[${reqId}] AUTH FAIL: token invalid or expired. expires=${expires} now=${now} diff=${exp - now}s fileId=${fileId}`);
        return res.status(403).json({ error: 'Invalid or expired stream token.', code: 'TOKEN_EXPIRED' });
    }

    if (!at) {
        console.warn(`[${reqId}] AUTH FAIL: missing Google access token (at param)`);
        return res.status(400).json({ error: 'Missing Google access token (at).', code: 'MISSING_AT' });
    }

    // Log token info for debugging (first/last 4 chars only)
    const atPreview = at.length > 8 ? `${at.slice(0, 4)}...${at.slice(-4)}` : '****';
    const expiresIn = parseInt(expires, 10) - Math.floor(Date.now() / 1000);

    // ── Build Google Drive request ────────────────────────────────────────────
    const driveUrl = new URL(`https://www.googleapis.com/drive/v3/files/${fileId}`);
    driveUrl.searchParams.set('alt', 'media');

    const headers = {
        'Authorization': `Bearer ${at}`,
        'User-Agent':    'CloudVault/2.0',
        'Connection':    'close',  // No keep-alive — prevents socket accumulation
    };

    if (req.headers.range) {
        headers['Range'] = req.headers.range;
    }

    activeStreams++;
    totalServed++;
    console.log(`[${reqId}] START file=${fileId} at=${atPreview} hmacExpiresIn=${expiresIn}s range=${req.headers.range || 'full'} active=${activeStreams}`);

    // ── Track cleanup state (prevent double-cleanup) ──────────────────────────
    let cleaned = false;
    const cleanup = (reason, upstreamReq) => {
        if (cleaned) return;
        cleaned = true;
        activeStreams = Math.max(0, activeStreams - 1);
        console.log(`[${reqId}] END (${reason}) activeStreams=${activeStreams}`);
        if (upstreamReq) {
            try { upstreamReq.destroy(); } catch (_) {}
        }
    };

    // ── Make the Google Drive request using native https ───────────────────────
    const upstreamReq = https.get(driveUrl.toString(), { headers, timeout: 60000 }, (upstream) => {
        const status = upstream.statusCode;

        // ── Handle Drive-level errors ─────────────────────────────────────────
        if (status >= 400) {
            // Consume the error body to free the socket
            let body = '';
            upstream.on('data', (chunk) => { body += chunk; });
            upstream.on('end', () => {
                cleanup(`drive-${status}`, upstreamReq);

                if (res.headersSent) return;

                let errorMsg;
                let errorCode;
                if (status === 401) {
                    errorMsg  = 'Google access token expired. Player will auto-refresh.';
                    errorCode = 'GOOGLE_TOKEN_EXPIRED';
                } else if (status === 403) {
                    errorMsg  = 'Google Drive access denied. Token may be expired.';
                    errorCode = 'GOOGLE_TOKEN_EXPIRED';
                } else if (status === 404) {
                    errorMsg  = `File ${fileId} not found in Google Drive.`;
                    errorCode = 'FILE_NOT_FOUND';
                } else if (status === 429) {
                    errorMsg  = 'Google Drive rate limit hit. Try again in a moment.';
                    errorCode = 'RATE_LIMITED';
                } else {
                    errorMsg  = `Google Drive returned HTTP ${status}.`;
                    errorCode = 'DRIVE_ERROR';
                }

                // Parse Google's error for detail
                let driveDetail = '';
                try {
                    const parsed = JSON.parse(body);
                    driveDetail = parsed?.error?.message || parsed?.error_description || '';
                } catch (_) {
                    driveDetail = body.slice(0, 300);
                }

                console.error(`[${reqId}] DRIVE ERROR ${status}: ${errorCode} | ${driveDetail || body.slice(0, 300)}`);
                res.status(status >= 500 ? 502 : status).json({ error: errorMsg, code: errorCode, driveDetail });
            });
            upstream.on('error', () => {
                cleanup(`drive-err-${status}`, upstreamReq);
            });
            return;
        }

        // ── Stream the response ───────────────────────────────────────────────
        const outStatus = status === 206 ? 206 : 200;

        res.writeHead(outStatus, {
            'Accept-Ranges':          'bytes',
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control':          'no-store',
            ...(upstream.headers['content-type']   && { 'Content-Type':   upstream.headers['content-type'] }),
            ...(upstream.headers['content-length'] && { 'Content-Length': upstream.headers['content-length'] }),
            ...(upstream.headers['content-range']  && { 'Content-Range':  upstream.headers['content-range'] }),
        });

        // Pipe Google Drive → Client
        upstream.pipe(res);

        // ── Cleanup on all exit paths ─────────────────────────────────────────

        // Client disconnected (user seeked or navigated away)
        req.on('close', () => {
            upstream.destroy();
            cleanup('client-close', upstreamReq);
        });

        // Upstream finished sending all data
        upstream.on('end', () => {
            cleanup('complete', upstreamReq);
        });

        // Upstream errored mid-stream
        upstream.on('error', (err) => {
            console.error(`[${reqId}] upstream error: ${err.message}`);
            cleanup('upstream-error', upstreamReq);
            if (!res.headersSent) {
                res.status(502).json({ error: 'Stream interrupted.', code: 'STREAM_ERROR' });
            } else {
                res.end();
            }
        });

        // Response stream errored (client-side issue)
        res.on('error', (err) => {
            console.error(`[${reqId}] response error: ${err.message}`);
            upstream.destroy();
            cleanup('response-error', upstreamReq);
        });
    });

    // ── Handle connection errors to Google ────────────────────────────────────
    upstreamReq.on('error', (err) => {
        cleanup(`connect-error: ${err.message}`, upstreamReq);
        if (!res.headersSent) {
            if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
                res.status(504).json({ error: 'Google Drive connection timed out.', code: 'TIMEOUT' });
            } else {
                res.status(502).json({ error: `Connection failed: ${err.message}`, code: 'CONNECT_ERROR' });
            }
        }
    });

    // ── Handle timeout on the request itself ──────────────────────────────────
    upstreamReq.on('timeout', () => {
        console.error(`[${reqId}] Connection to Google Drive timed out`);
        upstreamReq.destroy();
        cleanup('timeout', upstreamReq);
        if (!res.headersSent) {
            res.status(504).json({ error: 'Google Drive connection timed out.', code: 'TIMEOUT' });
        }
    });
});

// ── 404 fallback ──────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found.' }));

// ── Process-level guards (prevent silent crashes on Koyeb) ────────────────────
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err.message, err.stack);
    // Don't exit — let the process continue serving
});

process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled rejection:', reason);
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`[CloudVault Proxy v2.0] Listening on port ${PORT}`);
});
