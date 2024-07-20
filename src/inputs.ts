import {ProfilePictureType} from './constants';

import type {ValidationData, ValidationDataInputs, StringValidationPattern} from './validate';

const emailValidationPattern: StringValidationPattern = {
	pattern: /^[^@]+@[^@]+\.[^@]+$/,
	message: 'must be a valid email address',
};

export const sessionApiValidationData: ValidationData = {
	inputs: {
		sessionId: {
			type: 'string',
			required: false,
		},
		ip: {
			type: 'string',
			required: true,
		},
	},
};
export const authApiValidationData: ValidationData = {
	inputs: {
		target: {
			type: 'string',
			required: true,
			patterns: [
				{
					pattern: /chaos/,
					message: 'should be a valid target',
				},
			],
		},
		devPort: {
			type: 'string',
			required: false,
		},
	},
};

export const loginPageValidationData: ValidationData = {
	inputs: {
		email: {
			type: 'string',
			required: true,
			maxLength: 256,
			patterns: [emailValidationPattern],
		},
		password: {
			type: 'string',
			required: true,
		},
	},
	capitalise: true,
};

const userDetailsValidationInputs: ValidationDataInputs = {
	username: {
		type: 'string',
		required: true,
		patterns: [
			{
				pattern: /^\S*$/,
				message: 'must not contain any spaces',
			},
		],
	},
	email: {
		type: 'string',
		required: true,
		maxLength: 256,
		patterns: [emailValidationPattern],
	},
};
const passwordValidationInputs: ValidationDataInputs = {
	password: {
		type: 'string',
		required: true,
		minLength: 8,
		patterns: [
			{
				pattern: /[a-z]/,
				message: 'must contain at least one lowercase letter',
			},
			{
				pattern: /[A-Z]/,
				message: 'must contain at least one uppercase letter',
			},
			{
				pattern: /[0-9]/,
				message: 'must contain at least one number',
			},
			{
				pattern: /[^a-zA-Z0-9]/,
				message: 'must contain something other than a letter or number',
			},
		],
	},
	confirmPassword: {
		type: 'string',
		required: true,
		shouldMatch: ['password'],
	},
};
export const signupPageValidationData: ValidationData = {
	inputs: {
		...userDetailsValidationInputs,
		...passwordValidationInputs,
	},
	capitalise: true,
};
export const userDetailsValidationData: ValidationData = {
	inputs: userDetailsValidationInputs,
	capitalise: true,
};
export const changePasswordValidationData: ValidationData = {
	inputs: {
		...passwordValidationInputs,
		currentPassword: {
			type: 'string',
			required: true,
		},
	},
	capitalise: true,
};
export const profilePictureValidationData: ValidationData = {
	inputs: {
		profilePicture: {
			type: 'string',
			required: true,
			patterns: [
				{
					pattern: new RegExp(`^(${Object.values(ProfilePictureType).join('|')})$`),
					message: 'should be a valid profile picture type',
				},
			],
		},
	},
};
export const confirmEmailValidationData: ValidationData = {
	inputs: {
		authCode: {
			type: 'string',
			required: true,
			patterns: [
				{
					pattern: /^[A-Z0-9]{3}-[A-Z0-9]{3}$/,
					message: 'should be in the format 000-000',
				},
			],
		},
	},
	capitalise: true,
};
export const resetPasswordEmailValidationData: ValidationData = {
	inputs: {
		email: {
			type: 'string',
			required: true,
			maxLength: 256,
			patterns: [emailValidationPattern],
		},
	},
	capitalise: true,
};
export const resetPasswordValidationData: ValidationData = {
	inputs: {
		...passwordValidationInputs,
		token: {
			type: 'string',
			required: true,
		},
	},
	capitalise: true,
};
export const getUserValidationData: ValidationData = {
	inputs: {
		id: {
			type: 'string',
			required: false,
		},
		username: {
			type: 'string',
			required: false,
		},
	},
};
export const oauth2CodeValidationData: ValidationData = {
	inputs: {
		grant_type: {
			type: 'string',
			required: true,
		},
		code: {
			type: 'string',
			required: true,
		},
		client_id: {
			type: 'string',
			required: true,
		},
		client_secret: {
			type: 'string',
			required: true,
		},
	},
};

interface ValidationDataMapEntry {
	validationData: ValidationData;
	requiresAccount?: boolean;
	requiresBearerToken?: () => string;
}
export const apiValidationDataMap: {[key: string]: ValidationDataMapEntry} = {
	'session': {
		validationData: sessionApiValidationData,
		requiresBearerToken: () => process.env.SESSION_API_KEY || '',
	},
	'auth': {
		validationData: authApiValidationData,
		requiresAccount: true,
	},
	'login': {
		validationData: loginPageValidationData,
	},
	'signup': {
		validationData: signupPageValidationData,
	},
	'user/details': {
		validationData: userDetailsValidationData,
		requiresAccount: true,
	},
	'user/password': {
		validationData: changePasswordValidationData,
		requiresAccount: true,
	},
	'user/profile-picture': {
		validationData: profilePictureValidationData,
		requiresAccount: true,
	},
	'confirm-email': {
		validationData: confirmEmailValidationData,
	},
	'reset-password-email': {
		validationData: resetPasswordEmailValidationData,
	},
	'reset-password': {
		validationData: resetPasswordValidationData,
	},
	'get-user': {
		validationData: getUserValidationData,
	},
	'oauth2/token': {
		validationData: oauth2CodeValidationData,
	},
};
