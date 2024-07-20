import type User from './server/user';

interface OAuth2Scopes {
	user: boolean | {
		read: boolean;
		write: boolean;
	};
}

export interface OAuth2Client {
	id: string;
	name: string;
	picture: string;
	hostname: string;
	path: string;
	scope: OAuth2Scopes,
	clientSecret: string;
	authCheck?: (user: User) => boolean;
}

export const ssoScope = {user: true};

if (!process.env.CHAOS_CLIENT_SECRET) throw new Error('No chaos client secret defined');
if (!process.env.DOZZLE_CLIENT_SECRET) throw new Error('No dozzle client secret defined');

const oauth2Clients: OAuth2Client[] = [
	{
		id: 'chaos',
		name: 'Chaos Game Visualiser',
		picture: 'chaos.jpg',
		hostname: 'chaos.danielhoward.me',
		path: '/auth',
		scope: {
			user: {
				read: true,
				write: false,
			},
		},
		clientSecret: process.env.CHAOS_CLIENT_SECRET,
	},
	{
		id: 'dozzle',
		name: 'Dozzle Admin Console',
		picture: 'dozzle.jpg',
		hostname: 'admin.danielhoward.me',
		path: '/auth',
		scope: {
			user: {
				read: true,
				write: false,
			},
		},
		clientSecret: process.env.DOZZLE_CLIENT_SECRET,
		authCheck: (user) => user.admin,
	},
];

export default oauth2Clients.reduce<Record<string, OAuth2Client>>((dict, client) => {
	dict[client.id] = client;
	return dict;
}, {});
