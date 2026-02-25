"use strict";

const ANAMELEN = 28;
const AERRLEN = 64;
const DOMLEN = 48;
const DESKEYLEN = 7;
const AESKEYLEN = 16;
const CHALLEN = 8;
const NETCHLEN = 16;
const CONFIGLEN = 16;
const SECRETLEN = 32;
const PASSWDLEN = 28;
const NONCELEN = 32;
const PAKKEYLEN = 32;
const PAKSLEN = (448+7)/8|0;
const PAKPLEN = 4 * PAKSLEN;
const PAKHASHLEN = 2 * PAKPLEN;
const PAKXLEN = PAKSLEN;
const PAKYLEN = PAKSLEN;

const AuthTreq = 1;
const AuthChal = 2;
const AuthPass = 3;
const AuthOK = 4;
const AuthErr = 5;
const AuthMod = 6;
const AuthOKvar = 9;
const AuthPAK = 19;
const AuthTs = 64;
const AuthTc = 65;
const AuthAs = 66;
const AuthAc = 67;
const AuthTp = 68;

const PAKPRIVSZ = 4 + PAKXLEN + PAKYLEN;
const AUTHKEYSZ = DESKEYLEN + AESKEYLEN + PAKKEYLEN + PAKHASHLEN;

const TICKETPLAINLEN = 1 + CHALLEN + 2 * ANAMELEN + NONCELEN;
const AUTHENTPLAINLEN = 1 + CHALLEN + NONCELEN;
const TICKETLEN = 12 + CHALLEN + 2 * ANAMELEN + NONCELEN + 16;
const AUTHENTLEN = 12 + CHALLEN + NONCELEN + 16;

const Ticketreq = Struct([
	'type', U8,
	'authid', FixedString(ANAMELEN),
	'authdom', FixedString(DOMLEN),
	'chal', Bytes(CHALLEN),
	'hostid', FixedString(ANAMELEN),
	'uid', FixedString(ANAMELEN),
	'paky', Bytes(PAKYLEN)
]);
const Ticket = Struct([
	'num', U8,
	'chal', Bytes(CHALLEN),
	'cuid', FixedString(ANAMELEN),
	'suid', FixedString(ANAMELEN),
	'key', Bytes(NONCELEN)
]);
const Authenticator = Struct([
	'num', U8,
	'chal', Bytes(CHALLEN),
	'rand', Bytes(NONCELEN)
]);

function tsmemcmp(a, b, n)
{
	var diff;
	
	diff = 0;
	for(var i = 0; i < n; i++)
		diff |= a[i] != b[i];
	return diff;
}

function showError(msg) {
	let error = document.getElementById('error');
	if(!error)
		return;
	document.getElementById('thegrey').style.display = 'flex';
	error.style.display = 'block';
	error.style.whiteSpace = 'pre-wrap';
	error.textContent = msg;
	document.getElementById('login').style.display = 'grid';
	document.getElementById('loading').style.display = 'none';
}

function websockifyAdvice(url) {
	let u;
	try {
		u = new URL(url);
	} catch (e) {
		return null;
	}
	let port = u.port ? parseInt(u.port, 10) : (u.protocol === 'wss:' ? 443 : 80);
	let info = null;
	switch(port) {
	case 17019: info = {remote: 17019, local: 1234, config: 'rcpu_url'}; break;
	case 17010: info = {remote: 17010, local: 1236, config: 'ncpu_url'}; break;
	case 567: info = {remote: 567, local: 1235, config: 'auth_url'}; break;
	case 1234: info = {remote: 17019, local: 1234, config: 'rcpu_url'}; break;
	case 1236: info = {remote: 17010, local: 1236, config: 'ncpu_url'}; break;
	case 1235: info = {remote: 567, local: 1235, config: 'auth_url'}; break;
	default: return null;
	}
	return [
		"WebSocket connection failed.",
		"Run:",
		"  websockify " + info.local + " YOUR.SERVER:" + info.remote + " --verbose --traffic",
		"Then set `" + info.config + "` to `ws://localhost:" + info.local + "` in config.js."
	].join("\n");
}

function formatError(err) {
	if(err && err.ws_url) {
		let msg = websockifyAdvice(err.ws_url);
		if(msg)
			return msg;
	}
	if(err && err.toString)
		return err.toString();
	return String(err);
}

if(typeof window !== 'undefined') {
	window.reportWebsocketError = function(url) {
		let msg = websockifyAdvice(url);
		if(msg)
			showError(msg);
	};
}

function asrdresp(chan, len)
{
	return chan.read(b=>1).then(c => {
		switch(c[0]){
		case AuthOK:
			return chan.read(b=>len);
		case AuthErr:
			return chan.read(b=>64).then(e => {throw new Error("remote: " + from_cstr(e))});
		case AuthOKvar:
			return chan.read(b=>5).then(b => {
				var n = from_cstr(b)|0;
				if(n <= 0 || n > len)
					throw new Error("AS protocol botch");
				return chan.read(b=>n)
			});
		default:
			throw new Error("AS protocol botch: unexpected response type " + c[0]);
		}
	});
}

function convM2T(b, key)
{
	return withBufP(TICKETLEN, (buf, buf_array) => {
		buf_array().set(b);
		if(C.form1M2B(buf, TICKETLEN, key) < 0)
			throw new Error("?password mismatch with auth server");
		return unpack(Ticket, buf_array().slice());
	});
}

function convA2M(s, key)
{
	return withBuf(AUTHENTLEN, (buf, buf_array) => {
		buf_array().set(pack(Authenticator, s).data());
		C.form1B2M(buf, 1 + CHALLEN + NONCELEN, key);
		return buf_array().slice();
	});
}

function convM2A(b, key)
{
	return withBuf(AUTHENTLEN, (buf, buf_array) => {
		buf_array().set(b);
		if(C.form1M2B(buf, AUTHENTLEN, key) < 0)
			throw new Error("?you and auth server agree about password. ?server is confused.");
		return unpack(Authenticator, buf_array().slice());
	});
}

function inlinePAK(chan, authkey, tr, crand, cchal)
{
	return withBufP(PAKYLEN, (ybuf, ybuf_array) =>
	withBufP(PAKPRIVSZ, priv =>
	withBufP(PAKYLEN, (server_ybuf, server_ybuf_array) => {
		C.authpak_new(priv, authkey, ybuf, 1);
		return chan.write(ybuf_array())
		.then(() => {
			// Check if server sends tickets after PAK exchange
			return chan.read(b => {
				if(b.length >= 2*TICKETLEN)
					return 2*TICKETLEN;
				return 0;
			});
		})
		.then(ticketsOrEmpty => {
			if(ticketsOrEmpty && ticketsOrEmpty.length > 0)
				return ticketsOrEmpty;
			return null;
		})
		.then(tickets => {
			// Copy server's public key to WASM memory
			server_ybuf_array().set(tr.paky);
			if(C.authpak_finish(priv, authkey, server_ybuf))
				throw new Error("inlinePAK: authpak_finish failed - wrong password?");
			
			// Get PAK key for encryption - must be a proper Uint8Array for form1B2M
			let pakKeyPtr = authkey + AESKEYLEN + DESKEYLEN;
			let pakKey = new Uint8Array(Module.HEAPU8.subarray(pakKeyPtr, pakKeyPtr + PAKKEYLEN));
			
			// form1B2M uses a global counter that starts at 0
			// We need ticket to have counter=1 and authenticator to have counter=2
			// So we need to call form1B2M once with a dummy buffer to increment to 1
			withBuf(12, (dummybuf, dummybuf_array) => {
				dummybuf_array()[0] = AuthTs;
				C.form1B2M(dummybuf, 12, pakKey);
			});
			
			// Create a RANDOM session key (not derived from PAK key!)
			let sessionKey = new Uint8Array(NONCELEN);
			window.crypto.getRandomValues(sessionKey);
			
			// Create a ticket for inline PAK
			// Note: cuid and suid should just be the username, not user@domain
			let ticket = {
				num: AuthTs,  // Server ticket (encrypted with PAK key)
				chal: new Uint8Array(tr.chal),
				cuid: user,
				suid: user,
				key: sessionKey
			};
			// Encrypt the ticket (use PAK key for encryption)
			let ticketMsg = withBuf(TICKETLEN, (buf, buf_array) => {
				buf_array().set(pack(Ticket, ticket).data());
				C.form1B2M(buf, TICKETPLAINLEN, pakKey);
				return buf_array().slice();
			});
			
			// Create authenticator
			// Authenticator should use the server's challenge (tr.chal) to prove we received it
			let auth = {
				num: AuthAc, 
				rand: new Uint8Array(crand.subarray(0, NONCELEN)), 
				chal: new Uint8Array(tr.chal)
			};
			let authMsg = withBuf(AUTHENTLEN, (buf, buf_array) => {
				buf_array().set(pack(Authenticator, auth).data());
				C.form1B2M(buf, 1 + CHALLEN + NONCELEN, pakKey);
				return buf_array().slice();
			});
			
			// Combine ticket + authenticator into single 192-byte message
			// This matches what the strace shows - they must be sent together
			let combined = new Uint8Array(TICKETLEN + AUTHENTLEN);
			combined.set(ticketMsg, 0);
			combined.set(authMsg, TICKETLEN);
			return chan.write(combined)
			.then(() => {
				return chan.read(b => {
					if(b.length >= AUTHENTLEN) {
						return AUTHENTLEN;
					}
					return -1;
				});
			})
		.then(b => {
			if(!b) {
				throw new Error("inlinePAK: connection closed before server authenticator");
			}
			let serverAuth = convM2A(b, sessionKey);
			if(serverAuth.num != AuthAs || tsmemcmp(serverAuth.chal, cchal, CHALLEN) != 0)
				throw new Error("inlinePAK: authenticator verification failed");
				crand.subarray(NONCELEN).set(serverAuth.rand);
				
				// Derive final secret using hkdf
				var ai = {
					suid: user,
					cuid: user,
				};
				ai.secret = withBuf(256, (secret, secret_array) => {
					C.hkdf_x_plan9(crand, sessionKey, secret);
					return secret_array().slice();
				});
				return ai;
			})
			.catch(err => {
				throw err;
			});
		});
	})));
}

function mkservertickets(authkey, tr, serverPaky) {
	if(tr.authid && tr.hostid && tr.authid !== tr.hostid) {
		throw new Error("mkservertickets: authid != hostid; auth server required");
	}
	let usePak = !!serverPaky;
	return withBufP(PAKYLEN, (ybuf, ybuf_array) =>
	withBufP(PAKPRIVSZ, priv =>
	withBufP(PAKYLEN, (server_ybuf, server_ybuf_array) => {
		let authServerY = null;
		if(usePak) {
			server_ybuf_array().set(serverPaky);
			C.authpak_new(priv, authkey, ybuf, 0);
			if(C.authpak_finish(priv, authkey, server_ybuf))
				throw new Error("mkservertickets: authpak_finish failed");
			authServerY = ybuf_array().slice();
		}
		let pakKeyPtr = authkey + AESKEYLEN + DESKEYLEN;
		let pakKey = new Uint8Array(Module.HEAPU8.subarray(pakKeyPtr, pakKeyPtr + PAKKEYLEN));
		let sessionKey = new Uint8Array(NONCELEN);
		window.crypto.getRandomValues(sessionKey);
		let ticket = {
			num: AuthTc,
			chal: new Uint8Array(tr.chal),
			cuid: user,
			suid: user,
			key: sessionKey
		};
		let clientTicket = withBuf(TICKETLEN, (buf, buf_array) => {
			buf_array().set(pack(Ticket, ticket).data());
			C.form1B2M(buf, TICKETPLAINLEN, pakKey);
			return buf_array().slice();
		});
		ticket.num = AuthTs;
		let serverTicket = withBuf(TICKETLEN, (buf, buf_array) => {
			buf_array().set(pack(Ticket, ticket).data());
			C.form1B2M(buf, TICKETPLAINLEN, pakKey);
			return buf_array().slice();
		});
		let combined = new Uint8Array(2 * TICKETLEN);
		combined.set(clientTicket, 0);
		combined.set(serverTicket, TICKETLEN);
		return {tickets: combined, y: authServerY};
	})));
}

function getastickets(authkey, tr)
{
	return withBufP(PAKYLEN, (ybuf, ybuf_array) =>
	withBufP(PAKPRIVSZ, priv =>
	withBufP(PAKYLEN, (as_ybuf, as_ybuf_array) => {
		return dial(auth_url).then(chan => {
			tr.type = AuthPAK;
			return chan.write(pack(Ticketreq, tr).data())
			.then(() => {
				C.authpak_new(priv, authkey, ybuf, 1);
				return chan.write(ybuf_array());
			}).then(() => {
				return asrdresp(chan, PAKYLEN);
			}).then(buf => {
				as_ybuf_array().set(buf);
				if(C.authpak_finish(priv, authkey, as_ybuf))
					throw new Error("getastickets: authpak_finish failed");
				tr.type = AuthTreq;
				return chan.write(pack(Ticketreq, tr).data());
			}).then(() => {
				return asrdresp(chan, 0);
			}).then(() => {
				return chan.read(b=>2*TICKETLEN);
			}).then(tickets => {
				return {tickets, y: as_ybuf_array().slice()};
			});
		});
	})));
}

function gettickets(authkey, tr) {
	let serverPaky = tr.paky;
	if(typeof auth_url !== 'undefined' && auth_url) {
		return getastickets(authkey, tr).catch(() => {
			return mkservertickets(authkey, tr, serverPaky);
		});
	}
	return mkservertickets(authkey, tr, serverPaky);
}

function dp9ik(chan, dom) {
	var crand, cchal;
	var tr;
	var authkey, auth;
	var sticket, cticket;
		
	return withBufP(AUTHKEYSZ, authkey => {
		crand = new Uint8Array(2*NONCELEN);
		cchal = new Uint8Array(CHALLEN);
		window.crypto.getRandomValues(crand);
		window.crypto.getRandomValues(cchal);
		
		return chan.write(cchal)
		.then(() => {
			return chan.read(b=>Ticketreq.len);
		})
		.then(b => {
			tr = unpack(Ticketreq, b);
			var hasPaky = !tr.paky.every(b => b === 0);
			var useInlinePak = (typeof use_inline_pak !== 'undefined' && use_inline_pak);
			// Use what the server sent for authid/authdom, but set our own hostid/uid
			tr.hostid = user;
			tr.uid = user;
			
			// Try using the server's authid for authpak_hash
			let authUser = tr.authid || user;
			C.passtokey(authkey, password);
			C.authpak_hash(authkey, authUser);
			
			if(hasPaky && useInlinePak) {
				// Optional inline PAK on the same connection
				return inlinePAK(chan, authkey, tr, crand, cchal);
			}
			// Default: use auth server tickets (matches drawterm behavior)
			return gettickets(authkey, tr);
		}).then(result => {
			if(result && result.suid) {
				// Inline PAK returned auth info directly
				return result;
			}
			
			// Traditional flow with tickets
			var tickets = result.tickets || result;
			var authServerY = result.y;
			sticket = tickets.subarray(TICKETLEN);
			let k = Module.HEAPU8.subarray(authkey + AESKEYLEN + DESKEYLEN, authkey + AESKEYLEN + DESKEYLEN + PAKKEYLEN);
			return convM2T(tickets.subarray(0, TICKETLEN), k)
			.then(tick => {
				cticket = tick;
				if(authServerY && authServerY.length === PAKYLEN) {
					return chan.write(authServerY);
				}
			}).then(() => {
				return chan.write(sticket);
			})
			.then(() => {
				let auth = {num: AuthAc, rand: crand.subarray(0, NONCELEN), chal: tr.chal};
				return chan.write(convA2M(auth, cticket.key));
			}).then(() => chan.read(b=>AUTHENTLEN))
			.then(b => {
				auth = convM2A(b, cticket.key);
				if(auth.num != AuthAs || tsmemcmp(auth.chal, cchal, CHALLEN) != 0)
					throw new Error("protocol botch");
				crand.subarray(NONCELEN).set(auth.rand);
				var ai = {
					suid: cticket.suid,
					cuid: cticket.cuid,
				};
				ai.secret = withBuf(256, (secret, secret_array) => {
					C.hkdf_x_plan9(crand, cticket.key, secret);
					return secret_array().slice();
				});
				return ai;
			});
		})
		.then(ai => ai)
		.finally(() => {
			if(cticket){
				cticket.key.fill(0);
				cticket.chal.fill(0);
			}
			if(sticket)
				sticket.fill(0);
			C.memset(authkey, 0, AUTHKEYSZ);
			crand.fill(0);
			cchal.fill(0);
		});
	});
}

function p9any(chan) {
	var v2, dom;
	
	return readstr(chan).then(str => {
		v2 = str.startsWith("v2 ");
		if(v2)
			str = str.substr(4);
		var doms = str
			.split(' ')
			.filter(s => s.startsWith('dp9ik@'))
			.map(s => s.substr(6));
		if(doms.length === 0)
			throw new Error("server did not offer dp9ik");
		// Use configured domain if available, otherwise use server's first offered domain
		dom = (typeof domain !== 'undefined' && domain) ? domain : doms[0];
		return chan.write(new TextEncoder("utf-8").encode('dp9ik ' + dom + '\0'));
	}).then(() => {
		if(v2)
			return readstr(chan).then(s => {
				if(s != 'OK')
					throw new Error('did not get OK in p9any: got ' + s);
			});
	}).then(() => dp9ik(chan, dom));
}

function resolveRcpuUrl() {
	try {
		let u = new URL(rcpu_url);
		if(u.port === "17010") {
			if(typeof ncpu_url !== 'undefined' && ncpu_url) {
				return ncpu_url;
			}
			showError(websockifyAdvice("ws://YOUR.SERVER:17010") || "ncpu_url is not set");
		}
	} catch (e) {
	}
	return rcpu_url;
}

function rcpu(failure) {
	const script = 
"syscall fversion 0 65536 buf 256 >/dev/null >[2=1]\n" + 
"mount -nc /fd/0 /mnt/term || exit\n" + 
"bind -q /mnt/term/dev/cons /dev/cons\n" + 
"if(test -r /mnt/term/dev/kbd){\n" + 
"	</dev/cons >/dev/cons >[2=1] aux/kbdfs -dq -m /mnt/term/dev\n" + 
"	bind -q /mnt/term/dev/cons /dev/cons\n" + 
"}\n" + 
"</dev/cons >/dev/cons >[2=1] service=cpu rc -li\n" + 
"echo -n hangup >/proc/$pid/notepg\n";
	
	const url = resolveRcpuUrl();
	return dial(url)
	.then(rawchan => {
		return p9any(rawchan).then(ai => {
			return tlsClient(rawchan, ai.secret);
		}).catch(failure);
	})
	.then(chan => {
		if(chan)
			return chan.write(new TextEncoder("utf-8").encode(script.length + "\n" + script))
			.then(() => chan);
	})
	.catch(failure);
}

function main() {
	if(user === undefined || user === null || password === undefined || password === null){
		document.getElementById('loading').style.display = 'none';
		document.getElementById('login').style.display = 'grid';
		if(user !== undefined){
			document.getElementById('user').value = user;
			document.getElementById('password').focus();
		}else
			document.getElementById('user').focus();
	}else
		go(true);
}

function go(no_ui) {
	if(!no_ui){
		user = document.getElementById('user').value;
		password = document.getElementById('password').value;
	}
	document.getElementById('login').style.display = 'none';
	document.getElementById('loading').style.display = '';
	rcpu(e => {
		showError(formatError(e));
		password = undefined;
		main();
	}).then(chan => {
		if(chan){
			document.getElementById('thegrey').style.display = 'none';
			document.getElementById('loading').style.display = 'none';
			document.getElementById('canvas').style.display = 'block';
			devcons();
			devdraw();
			devaudio();
			return NineP(chan);
		}
	});
}
