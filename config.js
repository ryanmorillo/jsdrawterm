/* connect to cpu server, port 17019 */
var rcpu_url = "ws://localhost:1234";

/* optional: new window (ncpu) proxy, port 17010 on server */
var ncpu_url = "ws://localhost:1236";

/* connect to auth server, port 567 */
/* Auth server is on the same host as CPU server in 9front */
var auth_url = "ws://localhost:1235";

/* mouse safety:
 * when enabled, multi-button chords are blocked unless modifier is held.
 * modifier: "alt" | "ctrl" | "shift" | "meta"
 */
var safe_mouse_mode = true;
var safe_mouse_modifier = "alt";

/* pointer lock:
 * click canvas to lock pointer (Esc releases lock).
 */
var pointer_lock_mode = true;

/* you can set the following items to undefined if you want them queried */

/* default user */
//var user = undefined;
var user = 'USER';

/* default password */
//var password = undefined;
var password = localStorage.getItem('drawterm password');
var domain = 'DOMAIN.TLD';
var dom = 'DOMAIN.TLD';
