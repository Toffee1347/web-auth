import type User from './user';

export interface RawSession {
	id: string;
	ip: string;
	expires: string;
	user_id: string | null;
	wait_for_auth_user_id: string | null;
}
export interface Session<T = null> {
	user: User | T;
	waitForAuthUser: User | null;
}

export interface RawUser {
	id: string;
	username: string;
	email: string;
	profile_picture: ProfilePictureType;
	created: string;
	last_updated: string;
	auth_code: string;
	auth_code_expires: string;
	password_reset_token: string;
	password_reset_token_expires: string;
	admin: boolean;
}

// export interface RawAccessTokenData {
// 	user_id: string;
// 	target: string;
// 	expires: string;
// }
// export interface AccessTokenData {
// 	user: User;
// 	target: string;
// 	expires: Date;
// }

export interface RawOAuth2CodeData {
	user_id: string;
	client_id: string;
	expires: string;
}
export interface RawRefreshTokenData {
	user_id: string;
	client_id: string;
	expires: string;
}

export interface SessionApiRequestBody {
	sessionId: string | undefined;
	ip: string;
}
