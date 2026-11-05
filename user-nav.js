/*
 * brAIght sidebar for the Student and Jobseeker pages -- one place to edit the links.
 *
 * Pages contain  <div class="user-layout"><aside id="user-nav"></aside><main id="app">...</main></div>
 * and load this script. It also injects the layout and sidebar styles, so the pages
 * only need their own content styles. The link for the current page is highlighted.
 */
(function () {
  'use strict';

  var box = document.getElementById('user-nav');
  if (!box) return;

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // "My Workspace" goes to the page for this user's type.
  var home = 'Workspace.html';
  try {
    var u = JSON.parse(sessionStorage.getItem('braight_user') || 'null');
    var t = String((u && u.userType) || '').toLowerCase().replace(/\s+/g, '');
    if (t === 'student') home = 'StudentWorkspace.html';
    else if (t === 'jobseeker') home = 'JobseekerWorkspace.html';
  } catch (e) { /* keep the fallback */ }

  var LINKS = [
    { label: 'My Workspace', href: home, match: ['studentworkspace.html', 'jobseekerworkspace.html', 'workspace.html'] },
    { label: 'My Payments', href: 'MyPayments.html' },
    { label: 'My Products', href: 'MyProducts.html' },
    { label: 'My Documents', href: 'MyDocuments.html' }
  ];

  var current = (location.pathname.split('/').pop() || '').toLowerCase();

  var style = document.createElement('style');
  style.textContent =
    '.user-layout{display:grid;grid-template-columns:230px minmax(0,1fr);align-items:start;min-height:60vh}' +
    '.user-sidebar{position:sticky;top:76px;margin:24px 0 24px 24px;padding:16px 12px;background:var(--panel,#FBFCFD);border:1px solid var(--border,#DCE3EC);border-radius:12px}' +
    '.user-sidebar .side-title{font-size:12px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;color:var(--label,#8793A3);padding:0 10px 8px}' +
    '.user-sidebar nav{display:flex;flex-direction:column;gap:2px;flex-wrap:nowrap;font-size:15px}' +
    '.user-sidebar a.side-link{display:block;padding:9px 10px;border-radius:8px;border-bottom:none;text-decoration:none;color:var(--sub,#5B6B7D);border-left:3px solid transparent}' +
    '.user-sidebar a.side-link:hover{background:var(--border,#DCE3EC);color:var(--navy,#17324F)}' +
    '.user-sidebar a.side-link.on{color:var(--navy,#17324F);font-weight:600;border-left-color:var(--amber,#C89B5C);background:var(--bg,#fff)}' +
    '.user-sidebar a.side-link:focus-visible{outline:2px solid var(--amber,#C89B5C);outline-offset:2px}' +
    '.user-layout main .wrap{max-width:none;padding:0 clamp(16px,3vw,36px)}' +
    '@media (max-width:820px){' +
      '.user-layout{grid-template-columns:minmax(0,1fr)}' +
      '.user-sidebar{position:static;margin:16px 16px 0;padding:10px}' +
      '.user-sidebar .side-title{display:none}' +
      '.user-sidebar nav{flex-direction:row;flex-wrap:wrap;gap:6px}' +
      '.user-sidebar a.side-link{border-left:none;border:1px solid var(--border,#DCE3EC);padding:7px 12px}' +
      '.user-sidebar a.side-link.on{border-color:var(--amber,#C89B5C)}' +
    '}';
  document.head.appendChild(style);

  box.className = 'user-sidebar';
  box.setAttribute('aria-label', 'My account');
  box.innerHTML = '<div class="side-title">My account</div><nav>' + LINKS.map(function (l) {
    var pages = [l.href.toLowerCase()].concat(l.match || []);
    var on = pages.indexOf(current) !== -1;
    return '<a class="side-link' + (on ? ' on' : '') + '" href="' + esc(l.href) + '"' + (on ? ' aria-current="page"' : '') + '>' + esc(l.label) + '</a>';
  }).join('') + '</nav>';
})();
