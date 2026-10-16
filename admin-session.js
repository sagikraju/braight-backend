/*
 * brAIght admin session helper -- shared by every admin page.
 *
 * Usage (at the end of <body>):
 *   <script src="admin-session.js"></script>
 *   <script>
 *     const admin = AdminSession.init({ onSessionEnd: () => { ...clear the page... } });
 *     if (admin) { ...load page data with AdminSession.apiFetch(...) }
 *   </script>
 *
 * It provides: session check, 30-second inactivity timeout with a popup,
 * heartbeat to keep the server-side session alive, authenticated fetch,
 * and logout that releases the single admin session.
 */
(function () {
  'use strict';

  var API_BASE = 'https://braight-backend.onrender.com';
  var STORAGE_KEY = 'braight_user';
  var IDLE_LIMIT_MS = 30 * 1000;   // log out after 30 seconds without activity
  var HEARTBEAT_MS = 10 * 1000;    // tell the server we're still active (only if there was activity)

  var user = null;
  var token = null;
  var onSessionEnd = null;
  var ended = false;
  var lastActivity = Date.now();
  var lastPing = Date.now();
  var idleTimer = null;
  var heartbeatTimer = null;
  var logoutPromise = Promise.resolve();

  function readSession() {
    try { return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || 'null'); }
    catch (e) { return null; }
  }

  function authHeaders(extra) {
    var h = { 'Authorization': 'Bearer ' + token };
    if (extra) { for (var k in extra) { if (Object.prototype.hasOwnProperty.call(extra, k)) h[k] = extra[k]; } }
    return h;
  }

  function withTimeout(promise, ms) {
    return Promise.race([promise, new Promise(function (resolve) { setTimeout(resolve, ms); })]);
  }

  function serverLogout() {
    return fetch(API_BASE + '/api/admin/logout', {
      method: 'POST',
      headers: authHeaders(),
      keepalive: true
    }).catch(function () {});
  }

  /* ---------- Timeout popup (injected so every page gets the same one) ---------- */

  function injectModal() {
    var style = document.createElement('style');
    style.textContent =
      '.as-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.65);z-index:1000;justify-content:center;align-items:center;}' +
      '.as-modal{background:var(--panel,#FBFCFD);border:1px solid var(--border,#DCE3EC);border-radius:12px;padding:28px;max-width:400px;width:90%;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,0.15);}' +
      '.as-modal h3{font-family:"Source Serif 4",Georgia,serif;color:var(--navy,#17324F);margin:0 0 12px;font-size:20px;}' +
      '.as-modal p{color:var(--sub,#5B6B7D);margin:0 0 20px;font-size:15px;}' +
      '.as-btn{padding:10px 20px;border-radius:6px;font-weight:600;font-size:14px;cursor:pointer;border:none;font-family:inherit;background:var(--amber,#C89B5C);color:#17324F;}';
    document.head.appendChild(style);

    var overlay = document.createElement('div');
    overlay.className = 'as-overlay';
    overlay.id = 'as-timeout-modal';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'as-timeout-title');
    overlay.setAttribute('aria-describedby', 'as-timeout-message');
    overlay.innerHTML =
      '<div class="as-modal">' +
        '<h3 id="as-timeout-title">Session Timed Out</h3>' +
        '<p id="as-timeout-message">Your session has timed out. Please re-login.</p>' +
        '<button class="as-btn" id="as-relogin">Re-login</button>' +
      '</div>';
    document.body.appendChild(overlay);

    document.getElementById('as-relogin').addEventListener('click', function () {
      withTimeout(logoutPromise, 3000).then(function () {
        window.location.replace('Login.html');
      });
    });
  }

  /* ---------- Session lifecycle ---------- */

  function markActive() {
    if (!ended) lastActivity = Date.now();
  }

  function checkIdle() {
    if (!ended && Date.now() - lastActivity >= IDLE_LIMIT_MS) endSession();
  }

  function sendHeartbeat() {
    if (ended || lastActivity <= lastPing) return;   // nothing happened since the last ping
    lastPing = Date.now();
    apiFetch('/api/admin/heartbeat', { method: 'POST' }).catch(function () {
      /* network blip: the server-side timeout is the backstop */
    });
  }

  // Every admin API call goes through here; a 401 means the server no longer accepts this session.
  function apiFetch(path, options) {
    options = options || {};
    var opts = {};
    for (var k in options) { if (Object.prototype.hasOwnProperty.call(options, k)) opts[k] = options[k]; }
    opts.headers = authHeaders(options.headers);
    return fetch(API_BASE + path, opts).then(function (res) {
      if (res.status === 401) endSession();
      return res;
    });
  }

  // Idle timeout or server-side expiry: release the session, let the page wipe itself, show the popup.
  function endSession() {
    if (ended) return;
    ended = true;
    clearInterval(idleTimer);
    clearInterval(heartbeatTimer);
    logoutPromise = serverLogout();
    sessionStorage.removeItem(STORAGE_KEY);
    if (typeof onSessionEnd === 'function') {
      try { onSessionEnd(); } catch (e) { /* ignore page callback errors */ }
    }
    var overlay = document.getElementById('as-timeout-modal');
    if (overlay) {
      overlay.style.display = 'flex';
      document.getElementById('as-relogin').focus();
    }
  }

  function logout() {
    if (ended) return Promise.resolve();
    ended = true;
    clearInterval(idleTimer);
    clearInterval(heartbeatTimer);
    // Free the single admin session before leaving the page.
    return withTimeout(serverLogout(), 3000).then(function () {
      sessionStorage.removeItem(STORAGE_KEY);
      window.location.replace('Login.html');
    });
  }

  // Returns the logged-in admin's user object, or null (after redirecting to Login.html).
  function init(options) {
    options = options || {};
    onSessionEnd = options.onSessionEnd || null;

    var s = readSession();
    if (!s || String(s.userType || '').toUpperCase() !== 'ADMIN' || !s.sessionToken) {
      sessionStorage.removeItem(STORAGE_KEY);
      window.location.replace('Login.html');
      return null;
    }
    user = s;
    token = s.sessionToken;

    injectModal();

    // Sidebar links without a page yet do nothing.
    var soon = document.querySelectorAll('.side-link.soon');
    for (var i = 0; i < soon.length; i++) {
      soon[i].addEventListener('click', function (e) { e.preventDefault(); });
    }

    ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'wheel'].forEach(function (evt) {
      window.addEventListener(evt, markActive, { passive: true });
    });
    // Timestamps (not one setTimeout) so sleeping laptops / throttled background tabs still time out.
    idleTimer = setInterval(checkIdle, 1000);
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') checkIdle();
    });
    heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_MS);

    return user;
  }

  window.AdminSession = {
    init: init,
    apiFetch: apiFetch,
    logout: logout,
    isEnded: function () { return ended; }
  };
})();
