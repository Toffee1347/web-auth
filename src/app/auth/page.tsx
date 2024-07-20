import oauth2Clients from '../../oauth2-clients';
import {getSession} from './../../server/session';
import Link from './../components/link';
import MiddleIsland from './../components/middle-island';
import {getRedirectQueryForPage} from './../utils/get-redirect';
import Buttons from './buttons';

import {ArrowLongRightIcon} from '@heroicons/react/24/solid';
import Image from 'next/image';
import {redirect} from 'next/navigation';

import type {SearchParamsProps} from './../types.d';

export default function AuthPage({searchParams}: SearchParamsProps) {
	const session = getSession();

	const filteredSearchParams = Object.entries(searchParams).reduce((params, [key, value]) => {
		if (value !== undefined && !Array.isArray(value)) params[key] = value;
		return params;
	}, {} as Record<string, string>);

	if (!session.user) {
		const fullSearchParams = new URLSearchParams(filteredSearchParams).toString();
		redirect(`/login${getRedirectQueryForPage(`/auth?${fullSearchParams}`)}&hidenavbar`);
	}

	const targetValue = filteredSearchParams.target;
	const target = oauth2Clients[targetValue];
	if (!target) {
		return (
			<MiddleIsland>
				<p className="text-red-600 font-bold">
					{targetValue === '' ? (
						<>A target should be provided in the query parameters</>
					) : (
						<>{targetValue} is not a valid auth target</>
					)}
				</p>
			</MiddleIsland>
		);
	}

	return (
		<MiddleIsland>
			<div className="space-y-4 max-w-xs">
				<div className="flex gap-4 items-center justify-center">
					<Image className="rounded-full" width={100} height={100} alt="Auth Target Picture" src={`/static/img/${target.picture}`}/>
					<ArrowLongRightIcon className="h-6 w-6 text-gray-600 dark:text-gray-300"/>
					<Image className="rounded-full" width={100} height={100} alt="Account Target Picture" src={session.user.getProfilePictureUrl()}/>
				</div>
				<p className="text-lg">
					<b>{target.name}</b> is requesting to access your account
				</p>
				<p>
					Authorising as <b>{session.user.username}</b> <Link href="/logout">Not you?</Link>
				</p>
				<p>
					Clicking authorise will only allow <b>{target.name}</b> to have access to your name, email and profile picture
					(it will <b>not</b> be able to acccess your password)
				</p>
				<Buttons target={targetValue} devPort={filteredSearchParams.devport}/>
			</div>
		</MiddleIsland>
	);
}
