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

function asrdresp(chan, len)
{
	console.log('asrdresp: starting to read response, expecting', len, 'bytes');
	return chan.read(b=>1).then(c => {
		console.log('asrdresp: received response type:', c[0], '(AuthOK=4, AuthErr=5, AuthOKvar=9)');
		switch(c[0]){
		case AuthOK:
			console.log('asrdresp: AuthOK, reading', len, 'bytes');
			return chan.read(b=>len);
		case AuthErr:
			console.log('asrdresp: AuthErr, reading error message');
			return chan.read(b=>64).then(e => {throw new Error("remote: " + from_cstr(e))});
		case AuthOKvar:
			console.log('asrdresp: AuthOKvar, reading length');
			return chan.read(b=>5).then(b => {
				var n = from_cstr(b)|0;
				console.log('asrdresp: AuthOKvar length:', n);
				if(n <= 0 || n > len)
					throw new Error("AS protocol botch");
				return chan.read(b=>n)
			});
		default:
			throw new Error("AS protocol botch: unexpected response type " + c[0]);
		}
	}).catch(err => {
		console.error('asrdresp: error:', err);
		throw err;
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
	console.log('inlinePAK: starting PAK exchange');
	return withBufP(PAKYLEN, (ybuf, ybuf_array) =>
	withBufP(PAKPRIVSZ, priv =>
	withBufP(PAKYLEN, (server_ybuf, server_ybuf_array) => {
		C.authpak_new(priv, authkey, ybuf, 1);
		return chan.write(ybuf_array())
		.then(() => {
			// Check if server sends tickets after PAK exchange
			return chan.read(b => {
				if(b.length >= 2*TICKETLEN) {
					console.log('inlinePAK: server sent tickets');
					return 2*TICKETLEN;
				}
				return 0;
			});
		})
		.then(ticketsOrEmpty => {
			if(ticketsOrEmpty && ticketsOrEmpty.length > 0) {
				console.log('inlinePAK: processing server tickets');
				return ticketsOrEmpty;
			}
			return null;
		})
		.then(tickets => {
			// Copy server's public key to WASM memory
			server_ybuf_array().set(tr.paky);
			if(C.authpak_finish(priv, authkey, server_ybuf))
				throw new Error("inlinePAK: authpak_finish failed - wrong password?");
			console.log('inlinePAK: PAK complete, creating ticket+authenticator');
			
			// Get PAK key for encryption
			let pakKey = Module.HEAPU8.subarray(authkey + AESKEYLEN + DESKEYLEN, authkey + AESKEYLEN + DESKEYLEN + PAKKEYLEN);
			
			// HACK: The form1B2M counter needs to start at 1, not 0
			// Call it once with a dummy buffer to increment the counter
			withBuf(12, (dummybuf, dummybuf_array) => {
				dummybuf_array()[0] = AuthTs;
				C.form1B2M(dummybuf, 12, pakKey);
			});
			
			// Derive the session key from PAK shared secret
			let sessionKey = new Uint8Array(NONCELEN);
			let k = Module.HEAPU8.subarray(authkey + AESKEYLEN + DESKEYLEN, authkey + AESKEYLEN + DESKEYLEN + PAKKEYLEN);
			sessionKey.set(k.slice(0, NONCELEN));
			
			// Create a ticket for inline PAK
			let ticket = {
				num: AuthTs,  // Server ticket (encrypted with PAK key)
				chal: tr.chal,
				cuid: user,
				suid: user,
				key: sessionKey
			};
			
			// Encrypt the ticket (use PAK key for encryption)
			let pakKey = Module.HEAPU8.subarray(authkey + AESKEYLEN + DESKEYLEN, authkey + AESKEYLEN + DESKEYLEN + PAKKEYLEN);
			let ticketMsg = withBuf(TICKETLEN, (buf, buf_array) => {
				buf_array().set(pack(Ticket, ticket).data());
				C.form1B2M(buf, TICKETLEN, pakKey);
				return buf_array().slice();
			});
			
			// Create authenticator
			let auth = {num: AuthAc, rand: crand.subarray(0, NONCELEN), chal: tr.chal};
			let authMsg = convA2M(auth, sessionKey);
			
			// Combine ticket + authenticator into single 192-byte message
			// This matches what the strace shows - they must be sent together
			let combined = new Uint8Array(TICKETLEN + AUTHENTLEN);
			combined.set(ticketMsg, 0);
			combined.set(authMsg, TICKETLEN);
			console.log('inlinePAK: sending combined ticket+authenticator (192 bytes)');
			console.log('inlinePAK: first 32 bytes:', Array.from(combined.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' '));
			console.log('inlinePAK: ticket header:', Array.from(ticketMsg.slice(0, 12)).map(b => b.toString(16).padStart(2, '0')).join(' '));
			console.log('inlinePAK: auth header:', Array.from(authMsg.slice(0, 12)).map(b => b.toString(16).padStart(2, '0')).join(' '));
			
			return chan.write(combined)
			.then(() => {
				return chan.read(b => {
					if(b.length >= AUTHENTLEN) {
						return AUTHENTLEN;
					}
					if(b.length > 0) {
						console.log('inlinePAK: partial data received:', b.length, 'bytes, expected', AUTHENTLEN);
					}
					return -1;
				});
			})
			.then(b => {
				console.log('inlinePAK: received server authenticator, verifying');
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
				console.log('inlinePAK: authentication complete');
				return ai;
			})
			.catch(err => {
				console.error('inlinePAK: error during authentication:', err);
				throw err;
			});
		});
	})));
}

function getastickets(authkey, tr, cpuchan)
{
	console.log('getastickets: starting');
	return withBufP(PAKYLEN, (ybuf, ybuf_array) =>
	withBufP(PAKPRIVSZ, priv => {
		// Use separate auth server if auth_url is defined, otherwise use CPU server connection
		var authPromise = (typeof auth_url !== 'undefined' && auth_url) 
			? (console.log('getastickets: dialing separate auth server at', auth_url), dial(auth_url))
			: (console.log('getastickets: using CPU server for auth'), Promise.resolve(cpuchan));
		
		return authPromise.then(chan => {
			console.log('getastickets: connected to auth server');
			tr.type = AuthPAK;
			console.log('getastickets: sending ticketreq');
			return chan.write(pack(Ticketreq, tr).data())
			.then(() => {
				console.log('getastickets: generating PAK public key');
				C.authpak_new(priv, authkey, ybuf, 1);
				console.log('getastickets: sending PAK public key');
				return chan.write(ybuf_array());
			}).then(() => {
				console.log('getastickets: waiting for PAK response');
				return asrdresp(chan, 2*PAKYLEN);
			}
			).then(buf => {
				console.log('getastickets: received PAK response, finishing PAK');
				tr.paky.set(buf.subarray(0, PAKYLEN));
				ybuf_array().set(buf.subarray(PAKYLEN));
				if(C.authpak_finish(priv, authkey, ybuf))
					throw new Error("getastickets failure");
				console.log('getastickets: PAK complete, requesting tickets');
				tr.type = AuthTreq;
				return chan.write(pack(Ticketreq, tr).data());
			}).then(() => {
				console.log('getastickets: waiting for ticket response');
				return asrdresp(chan, 0);
			}
			).then(() => {
				console.log('getastickets: reading tickets');
				return chan.read(b=>2*TICKETLEN);
			}
			);
		});
	}));
}

function dp9ik(chan, dom) {
	var crand, cchal;
	var tr;
	var authkey, auth;
	var sticket, cticket;
		
	console.log('dp9ik: starting authentication');
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
			console.log('dp9ik: server provided PAK key, using inline PAK');
			
			// Use what the server sent - don't overwrite!
			tr.hostid = user;
			tr.uid = user;
			C.passtokey(authkey, password);
			C.authpak_hash(authkey, tr.uid);
			
			if(hasPaky) {
				// Server provided its public key - do inline PAK on this connection
				return inlinePAK(chan, authkey, tr, crand, cchal);
			} else {
				// Need separate auth server connection
				console.log('dp9ik: no PAK key, using separate auth server');
				return getastickets(authkey, tr, chan);
			}
		}).then(result => {
			if(result && result.suid) {
				// Inline PAK returned auth info directly
				console.log('dp9ik: using inline PAK auth info');
				return result;
			}
			
			// Traditional flow with tickets
			console.log('dp9ik: processing tickets');
			var tickets = result;
			sticket = tickets.subarray(TICKETLEN);
			let k = Module.HEAPU8.subarray(authkey + AESKEYLEN + DESKEYLEN, authkey + AESKEYLEN + DESKEYLEN + PAKKEYLEN);
			console.log('dp9ik: decrypting client ticket');
			return convM2T(tickets.subarray(0, TICKETLEN), k)
			.then(tick => {
				console.log('dp9ik: client ticket decrypted');
				cticket = tick;
				console.log('dp9ik: sending server public key');
				return chan.write(tr.paky);
			}).then(() => {
				console.log('dp9ik: sending server ticket');
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
		.then(ai => {
			console.log('dp9ik: authentication complete');
			return ai;
		})
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
	
	console.log('rcpu: starting connection to', rcpu_url);
	return dial(rcpu_url)
	.then(rawchan => {
		console.log('rcpu: connected, starting p9any authentication');
		return p9any(rawchan).then(ai => {
			console.log('rcpu: authentication complete, ai.secret length:', ai.secret.length);
			console.log('rcpu: starting TLS with PSK');
			return tlsClient(rawchan, ai.secret);
		}).catch(failure);
	})
	.then(chan => {
		console.log('rcpu: TLS established, sending script');
		if(chan)
			return chan.write(new TextEncoder("utf-8").encode(script.length + "\n" + script))
			.then(() => chan);
	});
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
		document.getElementById('loading').style.display = 'none';
		document.getElementById('login').style.display = 'grid';
		document.getElementById('error').style.display = 'block';
		document.getElementById('error').innerHTML = e.toString();
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
