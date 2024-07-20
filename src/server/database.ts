import {Client} from 'pg';

import type {ProfilePictureType} from './../constants';
import type {RawSession, RawUser, RawAccessTokenData, RawOAuth2CodeData, RawRefreshTokenData} from './types.d';
import type {ClientConfig, QueryResult, QueryResultRow} from 'pg';

class Database {
	private client: Client;
	private connectPromise: Promise<void> | null;

	public constructor() {
		this.createClient();
		this.connect();
	}

	private async connect() {
		console.log(`Connecting to database ${this.client.database}`);
		try {
			this.connectPromise = this.client.connect();
			await this.connectPromise;
			console.log('Connected to database');
			this.connectPromise = null;
		} catch (err) {
			console.error('Error connecting to database', err);
		}
	}

	public async waitForConnection() {
		if (this.connectPromise) {
			await this.connectPromise;
		}
	}

	// This function is only used in development
	public async changeDatabase(database: string) {
		if (process.env.NODE_ENV === 'production') {
			throw new Error('This function should never be used in production');
		}

		console.log(`Disconnecting from database ${this.client.database}`);
		await this.client.end();

		this.createClient({database});
		await this.connect();
	}

	private async createClient(config?: ClientConfig) {
		this.client = new Client({
			user: process.env.PGUSER,
			host: process.env.PGHOST,
			password: process.env.PGPASSWORD,
			database: process.env.PGDATABASE,
			port: Number(process.env.PGPORT) || 5432,
			...config,
		});
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	public async query<T extends QueryResultRow>(sql: string, values?: any[]): Promise<QueryResult<T>> {
		if (process.env.NODE_ENV !== 'production' && process.env.LOG_QUERIES === 'true') {
			const sqlQuery = sql.split('\n').map((line) => '\t' + line).join('\n');
			console.log('Querying database:');
			console.log(sqlQuery);
			if (values) {
				console.log('With values:');
				console.log(values);
			}
		}

		return this.client.query<T>(sql, values);
	}

	public async close() {
		if (process.env.NODE_ENV !== 'production') {
			console.log('Closing database connection');
		}

		await this.client.end();
	}

	public async entryExists(table: string, ...whereQuery: {
		field: string,
		value: string,
		negate?: boolean,
	}[]): Promise<boolean> {
		let parameterIndex = 1;
		const parameters: string[] = [];
		const where = whereQuery.map((query) => {
			parameters.push(query.value);
			return `${query.field} ${query.negate ? '!' : ''}= $${parameterIndex++}`;
		}).join(' AND ');

		const {rows} = await this.query<{exists: boolean}>(
			`SELECT EXISTS(SELECT 1 FROM ${table} WHERE ${where}) AS exists`,
			parameters,
		);

		return rows[0].exists;
	}

	public async getSession(sessionId: string): Promise<RawSession | undefined> {
		const {rows} = await this.query<RawSession>(
			'SELECT id, ip, EXTRACT(EPOCH FROM expires) AS expires, user_id, wait_for_auth_user_id FROM sessions WHERE id = $1',
			[sessionId],
		);

		return rows[0];
	}

	public async createSession(sessionId: string, ip: string, maxAge: number) {
		await this.query(
			`INSERT INTO sessions (id, ip, expires) VALUES ($1, $2, NOW() + INTERVAL '${maxAge} seconds')`,
			[sessionId, ip],
		);
	}

	public async deleteSession(sessionId: string) {
		await this.query(
			'DELETE FROM sessions WHERE id = $1',
			[sessionId],
		);
	}

	public async updateSession(sessionId: string, userId: string | null, waitForAuthUserId: string | null) {
		await this.query(
			'UPDATE sessions SET user_id = $1, wait_for_auth_user_id = $2 WHERE id = $3',
			[userId, waitForAuthUserId, sessionId],
		);
	}

	public async getUser(userId: string): Promise<RawUser | undefined> {
		const {rows} = await this.query<RawUser>(
			`
				SELECT
					id,
					username,
					email,
					profile_picture,
					EXTRACT(EPOCH FROM created) AS created,
					EXTRACT(EPOCH FROM last_updated) AS last_updated,
					auth_code,
					EXTRACT(EPOCH FROM auth_code_expires) AS auth_code_expires,
					password_reset_token,
					EXTRACT(EPOCH FROM password_reset_token_expires) AS password_reset_token_expires,
					admin
				FROM users WHERE id = $1
			`,
			[userId],
		);

		return rows[0];
	}

	public async getUserId(email: string): Promise<string | undefined> {
		const {rows} = await this.query<{id: string}>(
			`SELECT id FROM users WHERE email = $1`,
			[email],
		);

		return rows[0]?.id;
	}

	public async getUserIdFromUsername(username: string): Promise<string | undefined> {
		const {rows} = await this.query<{id: string}>(
			`SELECT id FROM users WHERE username = $1`,
			[username],
		);

		return rows[0]?.id;
	}

	public async getUserPassword(userId: string): Promise<string | undefined> {
		const {rows} = await this.query<{password: string}>(
			`SELECT password FROM users WHERE id = $1`,
			[userId],
		);

		return rows[0]?.password;
	}

	public async createUser(userId: string, username: string, email: string, password: string) {
		await this.query(
			`INSERT INTO users (id, username, email, password) VALUES ($1, $2, $3, $4)`,
			[userId, username, email, password],
		);
	}

	public async editUserDetails(userId: string, username: string, email: string) {
		await this.query(
			'UPDATE users SET username = $1, email = $2 WHERE id = $3',
			[username, email, userId],
		);
	}

	public async changeUserPassword(userId: string, password: string) {
		await this.query(
			'UPDATE users SET password = $1 WHERE id = $2',
			[password, userId],
		);
	}

	public async changeProfilePicture(userId: string, profilePicture: ProfilePictureType) {
		await this.query(
			'UPDATE users SET profile_picture = $1 WHERE id = $2',
			[profilePicture, userId],
		);
	}

	public async setUserAuthCode(userId: string, authCode: string, expiry: number) {
		await this.query(
			`UPDATE users SET auth_code = $1, auth_code_expires = NOW() + INTERVAL '${expiry} SECONDS' WHERE id = $2`,
			[authCode, userId],
		);
	}

	public async clearUserAuthCode(userId: string) {
		await this.query(
			`UPDATE users SET auth_code = NULL, auth_code_expires = NULL WHERE id = $1`,
			[userId],
		);
	}

	public async setUserPasswordResetToken(userId: string, token: string, expiry: number) {
		await this.query(
			`UPDATE users SET password_reset_token = $1, password_reset_token_expires = NOW() + INTERVAL '${expiry} SECONDS' WHERE id = $2`,
			[token, userId],
		);
	}

	public async getUserWithPasswordResetToken(token: string): Promise<string | undefined> {
		const {rows} = await this.query(
			`SELECT id FROM users WHERE password_reset_token = $1`,
			[token],
		);

		return rows[0]?.id;
	}

	public async deletePasswordResetToken(userId: string) {
		await this.query(
			`UPDATE users SET password_reset_token = NULL, password_reset_token_expires = NULL WHERE id = $1`,
			[userId],
		);
	}

	// public async createAccessToken(token: string, userId: string, target: string, expiresSeconds: number) {
	// 	await this.query(
	// 		`INSERT INTO access_tokens (token, user_id, target, expires) VALUES ($1, $2, $3, NOW() + INTERVAL '${expiresSeconds} SECONDS')`,
	// 		[token, userId, target],
	// 	);
	// }

	// public async getAccessTokenData(token: string): Promise<RawAccessTokenData | undefined> {
	// 	const {rows} = await this.query<RawAccessTokenData>(
	// 		'SELECT user_id, target, EXTRACT(EPOCH FROM expires) AS expires FROM access_tokens WHERE token = $1',
	// 		[token],
	// 	);

	// 	return rows[0];
	// }

	// public async getAccessToken(userId: string, target: string): Promise<string | undefined> {
	// 	const {rows} = await this.query<{token: string}>(
	// 		'SELECT token FROM access_tokens WHERE user_id = $1 AND target = $2',
	// 		[userId, target],
	// 	);

	// 	return rows[0]?.token;
	// }

	// public async updateAccessTokenExpiry(token: string, expiresSeconds: number) {
	// 	await this.query(
	// 		`UPDATE access_tokens SET expires = NOW() + INTERVAL '${expiresSeconds} SECONDS' WHERE token = $1`,
	// 		[token],
	// 	);
	// }

	// public async deleteAccessToken(token: string) {
	// 	await this.query(
	// 		`DELETE FROM access_tokens WHERE token = $1`,
	// 		[token],
	// 	);
	// }

	public async createOAuth2Code(code: string, clientId: string, userId: string, expiresSeconds: number) {
		await this.query(
			`INSERT INTO ouath2_codes (code, user_id, client_id, expires) VALUES ($1, $2, $3, NOW() + INTERVAL '${expiresSeconds} SECONDS')`,
			[code, clientId, userId],
		);
	}

	public async getOAuth2CodeData(code: string): Promise<RawOAuth2CodeData | undefined> {
		const {rows} = await this.query<RawOAuth2CodeData>(
			'SELECT user_id, client_id, EXTRACT(EPOCH FROM expires) AS expires FROM ouath2_codes WHERE code = $1',
			[code],
		);

		return rows[0];
	}

	public async deleteOAuth2Code(code: string) {
		await this.query(
			`DELETE FROM ouath2_codes WHERE code = $1`,
			[code],
		);
	}

	public async createRefreshToken(token: string, userId: string, clientId: string, expiresSeconds: number) {
		await this.query(
			`INSERT INTO refresh_tokens (token, user_id, client_id, expires) VALUES ($1, $2, $3, NOW() + INTERVAL '${expiresSeconds} SECONDS')`,
			[token, clientId, userId],
		);
	}

	public async getRefreshTokenExpiry(token: string): Promise<string | undefined> {
		const {rows} = await this.query<{expires: string}>(
			'SELECT EXTRACT(EPOCH FROM expires) AS expires FROM refresh_tokens WHERE token = $1',
			[token],
		);

		return rows[0]?.expires;
	}

	public async deleteRefreshToken(token: string) {
		await this.query(
			`DELETE FROM refresh_tokens WHERE token = $1`,
			[token],
		);
	}

	public async createAccessToken(token: string, refreshToken: string, expiresSeconds: number) {
		await this.query(
			`INSERT INTO refresh_tokens (token, refresh_token, expires) VALUES ($1, $2, NOW() + INTERVAL '${expiresSeconds} SECONDS')`,
			[token, refreshToken],
		);
	}
}

const db = new Database();
export default db;
