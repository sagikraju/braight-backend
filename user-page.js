/*
 * Shared start-up for My Payments / My Products / My Documents:
 *   UserPage.start(function (user, root) { ...fill root... });
 * Checks the session (30-second idle timeout, one session per user), keeps the
 * page for Student and Jobseeker users, wires up Log Out, then calls render().
 */
(function () {
  'use strict';

  function norm(t) { return String(t || '').toLowerCase().replace(/\s+/g, ''); }

  function start(render) {
    var root = document.getElementById('app');
    // Fail closed: never show the page without the session script.
    if (typeof AppSession === 'undefined') {
      root.innerHTML = '<div class="wrap"><p class="lede">The session script (admin-session.js) did not load or is out of date. Please refresh the page (Ctrl+F5) or contact the administrator.</p></div>';
      return;
    }
    var user = AppSession.init({
      requireAdmin: false,
      onSessionEnd: function () { root.innerHTML = '<div class="wrap"><p class="lede">Session ended.</p></div>'; }
    });
    if (!user) return;   // not logged in: already redirected to Login.html

    var type = norm(user.userType);
    if (type === 'admin') { window.location.replace('AdminHome.html'); return; }
    if (type !== 'student' && type !== 'jobseeker') { window.location.replace('Workspace.html'); return; }

    document.getElementById('logout-btn').addEventListener('click', function () { AppSession.logout(); });
    render(user, root);
  }

  window.UserPage = { start: start };
})();
