export interface Env {}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext
	): Promise<Response> {
		try {
			const body = await request.json();
			const verify = await verifySlackRequest({
				signingSecret: '5d21573fcbf36327034639919d2eaaca', // https://api.slack.com/authentication/verifying-requests-from-slack#about
				body,
				headers: {
					slackRequestTimestamp: request.headers.get('x-slack-request-timestamp'),
					slackSignature: request.headers.get('x-slack-signature'),
				},
			});
			return new Response(JSON.stringify(verify));
		} catch (error) {
			return new Response(error);
		}
	},
};

async function verifySlackRequest(options: {
	signingSecret: string;
	body: { token: string; };
	headers: { slackRequestTimestamp: string; slackSignature: string };
}): Promise<boolean> {
	if (!options.signingSecret) {
		throw new Error(`slack signing secret is empty`);
	}

	if (!options.headers.slackRequestTimestamp || !options.headers.slackSignature) {
		throw new Error(`header x-slack-request-timestamp or x-slack-signature did not have the expected type (null)`);
	}

	if (+options.headers.slackRequestTimestamp < Date.now() - 60 * 5 * 1000) {
		throw new Error(`x-slack-request-timestamp must differ from system time by no more than 5
		 minutes or request is stale`);
	}

	const [signatureVersion, signatureHash] = options.headers.slackSignature.split('=');

	if (signatureVersion !== 'v0') {
		throw new Error(`unknown signature version`);
	}

	if (!signatureHash) {
		throw new Error(`signature mismatch`);
	}

	const enc = new TextEncoder();

	const cryptoSignature = Array.prototype.map.call(new Uint8Array(await crypto.subtle.sign(
		'HMAC',
		await crypto.subtle.importKey(
			"raw",
			await enc.encode(options.signingSecret),
			{
				name: "HMAC",
				hash: {name: "SHA-256"}
			},
			false,
			["sign", "verify"]
		),
		enc.encode(`${signatureVersion}:${options.headers.slackRequestTimestamp}:${JSON.stringify(options.body)}`)
	)), x => x.toString(16).padStart(2, '0')).join("");

	return cryptoSignature === signatureHash
}