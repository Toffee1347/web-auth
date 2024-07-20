import {ACCESS_TOKEN_EXPIRES_SECONDS, OAUTH2_CODE_EXPIRES_SECONDS, OAUTH2_TOKEN_LENGTH, REFRESH_TOKEN_EXPIRES_SECONDS} from './../constants';
import db from './database';
import User from './user';

import {v4 as uuid} from 'uuid';

import type {OAuth2Client} from './../oauth2-clients';

function generateToken(): string {
	// Each value generates to hex values
	const randomValues = new Uint8Array(Math.ceil(OAUTH2_TOKEN_LENGTH/2));
	crypto.getRandomValues(randomValues);
	return Array.from(randomValues)
		.map((value) => value.toString(16).padStart(2, '0'))
		.join('').substring(0, OAUTH2_TOKEN_LENGTH);
}

async function makeUniqueToken(table, field): Promise<string> {
	let token = '';
	while (token === '' || db.entryExists(table, {field, value: token})) {
		token = generateToken();
	}
	return token;
}

export async function makeOAuth2Code(client: OAuth2Client, user: User): Promise<string> {
	if (client.authCheck && !client.authCheck(user)) {
		throw new Error(`${user.id} is unable to make an OAuth2 code for ${client.id}`);
	}

	const code = await makeUniqueToken('ouath2_codes', 'code');
	await db.createOAuth2Code(code, client.id, user.id, OAUTH2_CODE_EXPIRES_SECONDS);
	return code;
}

export async function makeRefreshToken(code: string): Promise<{token: string} | {noCodeFound: boolean} | {codeExpired: boolean}> {
	const codeData = await db.getOAuth2CodeData(code);
	if (!codeData) return {noCodeFound: true};

	if (parseInt(codeData?.expires) < Date.now()) {
		await db.deleteOAuth2Code(code);
		return {codeExpired: true};
	}

	const token = await makeUniqueToken('refresh_tokens', 'token');
	await db.createRefreshToken(token, codeData.user_id, codeData.client_id, REFRESH_TOKEN_EXPIRES_SECONDS);
	await db.deleteOAuth2Code(code);

	return {token};
}

export async function makeAccessToken(refreshToken: string): Promise<{token: string} | {noFreshTokenFound: boolean} | {refreshTokenExpired: boolean}> {
	const refreshTokenExpiry = await db.getRefreshTokenExpiry(refreshToken);
	if (!refreshTokenExpiry) return {noFreshTokenFound: true};

	if (parseInt(refreshTokenExpiry) < Date.now()) {
		await db.deleteRefreshToken(refreshToken);
		return {refreshTokenExpired: true};
	}

	const token = await makeUniqueToken('access_tokens', 'token');
	await db.createAccessToken(token, refreshToken, ACCESS_TOKEN_EXPIRES_SECONDS);

	return {token};
}

// export async function makeAccessToken(target: string, user: User): Promise<string> {
// 	let token = '';

// 	const currentToken = await db.getAccessToken(user.id, target);
// 	if (currentToken) {
// 		await db.updateAccessTokenExpiry(currentToken, ACCESS_TOKEN_EXPIRES_SECONDS);
// 		token = currentToken;
// 	} else {
// 		while (token === '' || await db.entryExists('access_tokens', {field: 'token', value: token})) {
// 			token = uuid();
// 		}

// 		await db.createAccessToken(token, user.id, target, ACCESS_TOKEN_EXPIRES_SECONDS);
// 	}

// 	return new URLSearchParams({
// 		access_token: token,
// 		expires_in: ACCESS_TOKEN_EXPIRES_SECONDS.toString(),
// 	}).toString();
// }

// export async function getAccessTokenData(token: string): Promise<AccessTokenData | null> {
// 	const tokenData = await db.getAccessTokenData(token);
// 	if (!tokenData) return null;

// 	const expires = new Date(tokenData.expires);
// 	if (expires.getTime() < Date.now()) {
// 		db.deleteAccessToken(token);
// 		return null;
// 	}

// 	const user = await User.get(tokenData.user_id);

// 	return {
// 		user,
// 		target: tokenData.target,
// 		expires: new Date(tokenData.expires),
// 	};
// }
