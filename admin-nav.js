/*
 * brAIght admin sidebar -- one place to edit the links for every admin page.
 *
 * Each admin page has an empty <aside class="sidebar" id="admin-nav"></aside>
 * and loads this script (before admin-session.js). The link for the current
 * page is highlighted automatically.
 *   - "also": other pages that belong under the same link (e.g. UserDetail under User Profile)
 *   - "soon": no page yet; shown as "Soon" and does nothing when clicked
 */
(function () {
  'use strict';

  var GROUPS = [
    { title: 'Dashboard', links: [
      { label: 'User Profile', href: 'UserProfile.html', also: ['UserDetail.html'] },
      { label: 'Active Sessions', href: 'ActiveSessions.html' },
      { label: 'Server Dashboard', soon: true }
    ]},
    { title: 'Programs', links: [
      { label: 'Cohorts', href: 'Cohorts.html' },
      { label: 'Enrollments', href: 'Enrollments.html' },
      { label: 'Progress', href: 'Progress.html' },
      { label: 'Applications', href: 'Applications.html' }
    ]}
  ];

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  var box = document.getElementById('admin-nav');
  if (!box) return;
  var current = (location.pathname.split('/').pop() || '').toLowerCase();

  box.innerHTML = GROUPS.map(function (g, gi) {
    var links = g.links.map(function (l) {
      if (l.soon) {
        return '<a class="side-link soon" href="#" title="Coming soon">' + esc(l.label) + ' <span class="soon-tag">Soon</span></a>';
      }
      var pages = [l.href].concat(l.also || []).map(function (p) { return p.toLowerCase(); });
      var on = pages.indexOf(current) !== -1;
      return '<a class="side-link' + (on ? ' on' : '') + '" href="' + esc(l.href) + '"' + (on ? ' aria-current="page"' : '') + '>' + esc(l.label) + '</a>';
    }).join('');
    return '<div class="side-title"' + (gi > 0 ? ' style="margin-top:14px"' : '') + '>' + esc(g.title) + '</div><nav>' + links + '</nav>';
  }).join('');
})();
