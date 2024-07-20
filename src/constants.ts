export enum CookieName {
	SESSION = '0',
	COLOUR_SCHEME = '1',
	BROWSER_PREFERED_SCHEME = '2',
}
export const SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

export const OAUTH2_TOKEN_LENGTH = 50; // Must match token field length in access_tokens and refresh_token in schema.sql
export const OAUTH2_CODE_EXPIRES_SECONDS = 60; // 1 minute
export const ACCESS_TOKEN_EXPIRES_SECONDS = 60 * 5; // 10 minutes
export const REFRESH_TOKEN_EXPIRES_SECONDS = 60 * 60 * 24 * 30; // 30 days

export const EMAIL_AUTH_CODE_EXPIRES_MINUTES = 10;
export const RESET_PASSWORD_TOKEN_EXPIRES_MINUTES = 10;

export enum ColourScheme {
	BROWSER,
	LIGHT,
	DARK,
}
export const DEFAULT_COLOUR_SCHEME = ColourScheme.BROWSER;

export const REDIRECT_QUERY_PARAMETER_NAME = 'redirect';
export const DEFAULT_POST_LOGIN_REDIRECT = '/';

export const SIGNUP_PLACEHOLDER_USERNAMES = [
	'Rumpelstiltskin',
	'FashionForward',
	'NomNomNation',
	'RecipeRockstar',
	'TouristyTraveler',
	'TechyTechie',
	'FishFanatic',
];

// Should match schema.sql profile_picture
export enum ProfilePictureType {
	Custom = 'custom',
	Identicon = 'identicon',
	MonsterId = 'monsterid',
	Wavatar = 'wavatar',
	Retro = 'retro',
	Robohash = 'robohash',
}

export const hideNavbarPaths: string[] = [
	'/auth',
];
export const noSessionPaths: string[] = [
	'/api/session',
	'/api/oauth2/account',
	'/api/get-user',
];
