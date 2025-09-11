const jwt = require('jsonwebtoken');

// Sanitize room name (lowercase, alphanumeric + dash, max 60 chars)
function sanitizeRoomName(raw) {
    return (raw || '')
        .toLowerCase()
        .replace(/[^a-z0-9\- ]/g, '')
        .trim()
        .replace(/\s+/g, '-')
        .slice(0, 60);
}

function buildPayload({ appId, roomName, userName, isModerator, enableRecording, enableLivestreaming, enableTranscription, ttlSeconds, externalId, autoStartRecording, autoStartTranscription }) {
    const now = Math.floor(Date.now() / 1000);
    return {
        aud: 'jitsi',
        iss: 'chat',
        iat: now,
        exp: now + ttlSeconds,
        sub: appId,
        room: roomName,
        context: {
            user: {
                name: userName || (isModerator ? 'Moderator' : 'Participant'),
                moderator: isModerator ? 'true' : 'false'
            },
            features: {
                recording: enableRecording ? 'true' : 'false',
                livestreaming: enableLivestreaming ? 'true' : 'false',
                transcription: enableTranscription ? 'true' : 'false'
            },
            // Metadata custom folosită ulterior la maparea transcriptului / înregistrării la o conversație WhatsApp
            metadata: {
                externalId: externalId || null,
                autoStartRecording: !!autoStartRecording,
                autoStartTranscription: !!autoStartTranscription
            }
        }
    };
}

function signToken(payload, privateKey, apiKeyId) {
    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        header: { alg: 'RS256', kid: apiKeyId, typ: 'JWT' }
    });
}

module.exports = async function handler(request, response) {
    if (request.method !== 'POST') {
        return response.status(405).json({ error: 'Method Not Allowed' });
    }

    // Security check (simple API key header)
    const apiSecretKey = process.env.API_SECRET_KEY;
    const requestApiKey = request.headers['x-api-key'];
    if (!apiSecretKey || requestApiKey !== apiSecretKey) {
        return response.status(401).json({ error: 'Unauthorized' });
    }

    // Environment vars
    const appId = process.env.JAAS_APP_ID;
    const apiKeyId = process.env.JAAS_API_KEY_ID;
    const privateKeyEnv = process.env.JAAS_PRIVATE_KEY;
    if (!appId || !apiKeyId || !privateKeyEnv) {
        return response.status(500).json({ error: 'Server configuration error.' });
    }
    const privateKey = privateKeyEnv.replace(/\\n/g, '\n');

    // Body params
    const {
        roomName,
        // Identitate (noi câmpuri separate)
        moderatorName,
        participantName,
        // Backward compatibility (dacă vine userName îl folosim pentru moderator)
        userName,
        enableRecording = true,
        enableLivestreaming = false,
        enableTranscription = true,
        externalId,
        autoStartRecording = true,
        autoStartTranscription = true,
        ttlSeconds = 2 * 60 * 60
    } = request.body || {};

    if (!roomName) {
        return response.status(400).json({ error: 'roomName is required.' });
    }

    const cleanRoom = sanitizeRoomName(roomName);
    if (!cleanRoom) {
        return response.status(400).json({ error: 'Invalid roomName after sanitization.' });
    }

    try {
        // Participant token (toți din grup)
    const resolvedParticipantName = participantName || 'Participant';
    const resolvedModeratorName = moderatorName || userName || 'Moderator';

        const participantPayload = buildPayload({
            appId,
            roomName: cleanRoom,
            userName: resolvedParticipantName,
            isModerator: false,
            enableRecording: !!enableRecording,
            enableLivestreaming: !!enableLivestreaming,
            enableTranscription: !!enableTranscription,
            ttlSeconds,
            externalId,
            autoStartRecording,
            autoStartTranscription
        });
        const participantToken = signToken(participantPayload, privateKey, apiKeyId);
        const participantURL = `https://8x8.vc/${appId}/${cleanRoom}?jwt=${participantToken}`;

        // Moderator token (privat)
        const moderatorPayload = buildPayload({
            appId,
            roomName: cleanRoom,
            userName: resolvedModeratorName,
            isModerator: true,
            enableRecording: !!enableRecording,
            enableLivestreaming: !!enableLivestreaming,
            enableTranscription: !!enableTranscription,
            ttlSeconds,
            externalId,
            autoStartRecording,
            autoStartTranscription
        });
        const moderatorToken = signToken(moderatorPayload, privateKey, apiKeyId);
        const moderatorURL = `https://8x8.vc/${appId}/${cleanRoom}?jwt=${moderatorToken}`;

        return response.status(200).json({
            roomName: cleanRoom,
            participantURL,
            moderatorURL,
            expiresAt: new Date(participantPayload.exp * 1000).toISOString(),
            features: {
                recording: !!enableRecording,
                livestreaming: !!enableLivestreaming,
                transcription: !!enableTranscription
            },
            externalId: externalId || null,
            identities: {
                participant: { name: resolvedParticipantName },
                moderator: { name: resolvedModeratorName }
            }
        });
    } catch (err) {
        console.error('JWT generation error', err);
        return response.status(500).json({ error: 'Token generation failed.' });
    }
};