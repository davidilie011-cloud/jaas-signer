const jwt = require('jsonwebtoken');

export default function handler(request, response) {
    if (request.method !== 'POST') {
        return response.status(405).json({ error: 'Method Not Allowed' });
    }

    // Acestea vor fi citite din variabilele de mediu SECRETE din Vercel
    const appId = process.env.JAAS_APP_ID;
    const apiKeyId = process.env.JAAS_API_KEY_ID;
    const privateKey = process.env.JAAS_PRIVATE_KEY.replace(/\\n/g, '\n');

    if (!appId || !apiKeyId || !privateKey) {
        return response.status(500).json({ error: 'Server configuration error.' });
    }

    const { roomName } = request.body;
    if (!roomName) {
        return response.status(400).json({ error: 'roomName is required.' });
    }

    // Logica de semnare JWT rulează aici, pe serverul tău, nu în n8n
    const payload = {
        aud: "jitsi",
        iss: "chat",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (4 * 60 * 60),
        sub: appId,
        context: {
            user: { name: "Moderator", moderator: "true" },
            features: { "recording": "true" }
        },
        room: roomName
    };

    const header = { alg: 'RS256', kid: apiKeyId, typ: 'JWT' };
    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', header: header });
    const finalURL = `https://8x8.vc/${appId}/${roomName}?jwt=${token}`;

    // Trimite înapoi la n8n linkul gata generat
    response.status(200).json({ finalURL: finalURL });
}