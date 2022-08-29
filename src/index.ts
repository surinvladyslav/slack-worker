export interface Env {}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext
	): Promise<Response> {
		try {
			const {token} = await request.json();
			const requestTimestampSec = await request.headers.get('x-slack-request-timestamp') as string;
			const signature = await request.headers.get('x-slack-signature') as string;

			const verify = await verifySlackRequest({
				signingSecret: '5d21573fcbf36327034639919d2eaaca', // link to the documentation https://api.slack.com/authentication/verifying-requests-from-slack#verifying-requests-from-slack-using-signing-secrets__a-recipe-for-security__step-by-step-walk-through-for-validating-a-request
				body: {token},
				headers: {
					slackRequestTimestamp: JSON.parse(requestTimestampSec),
					slackSignature: signature,
				},
			});
			return new Response(JSON.stringify(verify));
		} catch (error) {
			return new Response(JSON.stringify(error));
		}
	},
};

async function verifySlackRequest(options: {
	signingSecret: string;
	body: {token: string;}
	headers: {slackRequestTimestamp: number; slackSignature: string};
}): Promise<boolean> {
	if (!options.signingSecret) {
		throw new Error(`slack signing secret is empty`);
	}

	const requestTimestampSec = options.headers.slackRequestTimestamp;
	const signature = options.headers.slackSignature;

	if (!requestTimestampSec || !signature) {
		throw new Error(`header x-slack-request-timestamp or x-slack-signature did not have the expected type (null)`);
	}

	const requestTimestampMaxDeltaMin = 5;
	const fiveMinutesAgoSec = Math.floor(Date.now() / 1000) - 60 * requestTimestampMaxDeltaMin;

	if (requestTimestampSec < fiveMinutesAgoSec) {
		throw new Error(`x-slack-request-timestamp must differ from system time by no more than ${requestTimestampMaxDeltaMin
		} minutes or request is stale`);
	}

	const [signatureVersion, signatureHash] = signature.split('=');

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
		enc.encode(`${signatureVersion}:${requestTimestampSec}:${JSON.stringify(options.body.token)}`)
	)), x => x.toString(16).padStart(2, '0')).join("");

	return cryptoSignature === signatureHash
}