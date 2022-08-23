export interface Env {}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext
	): Promise<Response> {
		try {
			const {token, challenge, type} = await request.json();
			const requestTimestampSec = await request.headers.get('x-slack-request-timestamp') as unknown as number;
			const signature = await request.headers.get('x-slack-signature') as string;

			const verify: boolean = await verifySlackRequest({
				signingSecret: '5d21573fcbf36327034639919d2eaaca',
				body: {token, challenge, type},
				headers: {
					"x-slack-request-timestamp": requestTimestampSec,
					"x-slack-signature": signature,
				},
			});
			// @ts-ignore
			return new Response(verify);
		} catch (error) {
			// @ts-ignore
			return new Response(error);
		}
	},
};

async function verifySlackRequest(options: {
	signingSecret: string;
	body: {token: string; challenge: string; type: string;}
	headers: {"x-slack-request-timestamp": number; "x-slack-signature": string};
}): Promise<boolean> {
	if (!options.signingSecret) {
		throw new Error(`slack signing secret is empty`);
	}

	const requestTimestampSec = options.headers['x-slack-request-timestamp'];
	const signature = options.headers['x-slack-signature'];
	let ourSignatureHash = null;

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
	await crypto.subtle.importKey(
		"raw",
		await enc.encode(options.signingSecret),
		{
			name: "HMAC",
			hash: {name: "SHA-256"}
		},
		false,
		["sign", "verify"]
	).then(async (key) => {
		await crypto.subtle.sign(
			"HMAC",
			key,
			enc.encode(`${signatureVersion}:${requestTimestampSec}:${JSON.stringify(options.body)}`)
		).then(signature => {
			const b = new Uint8Array(signature);
			ourSignatureHash = Array.prototype.map.call(b, x => x.toString(16).padStart(2, '0')).join("")
		});
	});

	return ourSignatureHash === signatureHash
}