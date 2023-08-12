import {CookieName, SESSION_COOKIE_MAX_AGE} from './../constants';

import type {SessionApiRequestBody, RawSession} from './types.d';
import type {NextURL} from 'next/dist/server/web/next-url';
import type {NextRequest, NextResponse} from 'next/server';

// Called by middleware to make a request to the session API
export async function loadSession(req: NextRequest, res: NextResponse) {
	if (req.nextUrl.pathname === '/api/session') return;

	const ip = req.ip ?? '::1';
	const sessionId = req.cookies.get(CookieName.SESSION)?.value;

	const finalSessionId = await makeSessionRequest(req.nextUrl, {sessionId, ip});
	if (finalSessionId === sessionId) return;

	res.cookies.set(CookieName.SESSION, finalSessionId, {
		maxAge: SESSION_COOKIE_MAX_AGE,
	});
}

async function makeSessionRequest(url: NextURL, body: SessionApiRequestBody): Promise<string> {
	const request = await fetch(`http://localhost:${url.port}/api/session`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${process.env.SESSION_API_KEY}`,
		},
		body: JSON.stringify(body),
	});

	if (!request.ok) {
		switch (request.status) {
		case 400: {
			const error = await request.json();
			throw new Error(`Request to session API failed: ${error.error}`);
		}
		default:
			throw new Error('Request to session API failed');
		}
	}

	const session = await request.json() as RawSession;
	return session.id;
}