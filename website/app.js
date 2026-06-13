/* ===========================================================
   Runveil — landing page interactions
   Vanilla JS, no dependencies, no build step.
   =========================================================== */
(function () {
  'use strict';

  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- Year ---------- */
  var yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  /* ---------- Nav: scrolled state + mobile toggle ---------- */
  var nav = document.getElementById('nav');
  var onScroll = function () {
    if (window.scrollY > 20) nav.classList.add('scrolled');
    else nav.classList.remove('scrolled');
  };
  onScroll();
  window.addEventListener('scroll', onScroll, { passive: true });

  var toggle = document.getElementById('nav-toggle');
  var links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', function () { links.classList.toggle('open'); });
    links.addEventListener('click', function (e) {
      if (e.target.tagName === 'A') links.classList.remove('open');
    });
  }

  /* ---------- Scroll reveal ---------- */
  var revealEls = document.querySelectorAll('[data-reveal]');
  if ('IntersectionObserver' in window && !prefersReduced) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var el = entry.target;
          var delay = Array.prototype.indexOf.call(el.parentNode.children, el) % 4;
          el.style.transitionDelay = (delay * 80) + 'ms';
          el.classList.add('in');

          // trigger counters / bars when revealed
          if (el.querySelector) {
            el.querySelectorAll('[data-count]').forEach(animateCount);
            el.querySelectorAll('.bar-fill').forEach(function (b) { b.classList.add('grow'); });
          }
          if (el.hasAttribute && el.hasAttribute('data-count')) animateCount(el);
          io.unobserve(el);
        }
      });
    }, { threshold: 0.18 });
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add('in'); });
    document.querySelectorAll('.bar-fill').forEach(function (b) { b.classList.add('grow'); });
    document.querySelectorAll('[data-count]').forEach(function (el) { el.textContent = el.getAttribute('data-count'); });
  }

  /* ---------- Animated number counters ---------- */
  function animateCount(el) {
    if (el.dataset.counted) return;
    el.dataset.counted = '1';
    var target = parseInt(el.getAttribute('data-count'), 10);
    var suffix = el.getAttribute('data-suffix') || '';
    if (prefersReduced) { el.textContent = target + suffix; return; }
    var dur = 1300, start = null;
    function tick(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(eased * target) + suffix;
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* ---------- Copy install command ---------- */
  var copyBtn = document.getElementById('copy-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var text = 'go install github.com/mdfaisal1/runveil/cmd/runveil@latest';
      var done = function () {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(function () { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('copied'); }, 1800);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(done);
      } else {
        var t = document.createElement('textarea');
        t.value = text; document.body.appendChild(t); t.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(t); done();
      }
    });
  }

  /* ---------- Live GitHub star count ---------- */
  (function fetchStars() {
    var targets = ['star-count-nav', 'star-count-hero', 'star-count-cta'];
    fetch('https://api.github.com/repos/mdfaisal1/runveil')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || typeof data.stargazers_count !== 'number') return;
        var n = data.stargazers_count;
        var label = n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);
        var nav = document.getElementById('star-count-nav');
        if (nav) nav.textContent = '★ ' + label;
        ['star-count-hero', 'star-count-cta'].forEach(function (id) {
          var el = document.getElementById(id);
          if (el) el.textContent = 'Star on GitHub · ' + label;
        });
      })
      .catch(function () { /* offline / rate-limited — leave default labels */ });
  })();

  /* ===========================================================
     Typed terminal — plays rv scan output when scrolled into view
     =========================================================== */
  var termBody = document.getElementById('terminal-body');
  var terminal = document.getElementById('terminal');
  var TERM_LINES = [
    { t: 350,  html: '<span class="t-prompt">$</span> <span class="t-cmd">rv scan ./package-lock.json --project checkout-api</span>' },
    { t: 500,  html: '<span class="t-dim">→ resolving 1,284 packages from lockfile…</span>' },
    { t: 600,  html: '<span class="t-dim">→ querying OSV vulnerability database…</span>' },
    { t: 650,  html: '<span class="t-warn">⚠  187 vulnerabilities found across dependencies</span>' },
    { t: 700,  html: '<span class="t-dim">→ building dependency &amp; call graph…</span>' },
    { t: 750,  html: '<span class="t-dim">→ correlating runtime evidence from agent…</span>' },
    { t: 500,  html: '' },
    { t: 300,  html: '<span class="t-cyan">REACHABLE FINDINGS</span>  <span class="t-dim">(6 of 187 — 97% noise removed)</span>' },
    { t: 250,  html: '<span class="t-bad">  ●</span> CVE-2024-21538  <span class="t-bad">CRITICAL</span>  cross-spawn   <span class="t-dim">reachable · 412 events</span>' },
    { t: 250,  html: '<span class="t-bad">  ●</span> CVE-2023-45857  <span class="t-warn">HIGH</span>      axios         <span class="t-dim">reachable · 88 events</span>' },
    { t: 250,  html: '<span class="t-warn">  ●</span> CVE-2024-28849  <span class="t-warn">HIGH</span>      follow-redir  <span class="t-dim">reachable · 31 events</span>' },
    { t: 250,  html: '<span class="t-dim">  ● …and 3 more reachable issues</span>' },
    { t: 500,  html: '' },
    { t: 300,  html: '<span class="t-good">✓ 181 dormant CVEs hidden</span> <span class="t-dim">— not on any executed code path</span>' },
    { t: 300,  html: '<span class="t-good">✓ scan complete in 3.2s</span>  <span class="t-dim">·  policy --fail-on critical → exit 1</span>' }
  ];

  var termStarted = false;
  function playTerminal() {
    if (termStarted || !termBody) return;
    termStarted = true;

    if (prefersReduced) {
      termBody.innerHTML = TERM_LINES.map(function (l) { return l.html; }).join('\n');
      return;
    }

    var i = 0;
    function next() {
      if (i >= TERM_LINES.length) {
        termBody.insertAdjacentHTML('beforeend', '<span class="cursor"></span>');
        return;
      }
      var line = TERM_LINES[i];
      termBody.insertAdjacentHTML('beforeend', line.html + '\n');
      terminal.scrollIntoView ? null : null;
      termBody.scrollTop = termBody.scrollHeight;
      i++;
      setTimeout(next, line.t);
    }
    next();
  }

  if (terminal && 'IntersectionObserver' in window) {
    var termIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { playTerminal(); termIO.disconnect(); } });
    }, { threshold: 0.35 });
    termIO.observe(terminal);
  } else {
    playTerminal();
  }

  /* ===========================================================
     Hero background — animated dependency graph.
     Nodes drift and connect; a travelling "reachability" pulse
     lights up a subset of nodes cyan (reachable) while the rest
     stay dim (dormant). Visual metaphor for the product.
     =========================================================== */
  var canvas = document.getElementById('graph-canvas');
  if (canvas && !prefersReduced) {
    var ctx = canvas.getContext('2d');
    var DPR = Math.min(window.devicePixelRatio || 1, 2);
    var W = 0, H = 0, nodes = [], mouse = { x: -9999, y: -9999 };

    function resize() {
      W = canvas.clientWidth; H = canvas.clientHeight;
      canvas.width = W * DPR; canvas.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      build();
    }

    function build() {
      var count = Math.max(28, Math.min(70, Math.floor((W * H) / 24000)));
      nodes = [];
      for (var i = 0; i < count; i++) {
        nodes.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.18,
          vy: (Math.random() - 0.5) * 0.18,
          r: 1.4 + Math.random() * 1.8,
          reachable: Math.random() < 0.22, // ~1 in 5 nodes "reachable"
          glow: 0
        });
      }
    }

    var t = 0;
    function frame() {
      ctx.clearRect(0, 0, W, H);
      t += 0.006;

      // links
      for (var i = 0; i < nodes.length; i++) {
        var a = nodes[i];
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > W) a.vx *= -1;
        if (a.y < 0 || a.y > H) a.vy *= -1;

        for (var j = i + 1; j < nodes.length; j++) {
          var b = nodes[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var d = Math.sqrt(dx * dx + dy * dy);
          if (d < 130) {
            var both = a.reachable && b.reachable;
            var alpha = (1 - d / 130) * (both ? 0.5 : 0.12);
            ctx.strokeStyle = both
              ? 'rgba(56,189,248,' + alpha + ')'
              : 'rgba(120,160,220,' + alpha + ')';
            ctx.lineWidth = both ? 1 : 0.6;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }

      // travelling reachability pulse across the width
      var pulseX = (Math.sin(t) * 0.5 + 0.5) * W;

      // nodes
      for (var k = 0; k < nodes.length; k++) {
        var n = nodes[k];
        var near = Math.abs(n.x - pulseX) < 80 && n.reachable;
        n.glow += ((near ? 1 : 0) - n.glow) * 0.06;

        // mouse interaction — gentle push
        var mdx = n.x - mouse.x, mdy = n.y - mouse.y;
        var md = Math.sqrt(mdx * mdx + mdy * mdy);
        if (md < 120) { n.x += mdx / md * 0.6; n.y += mdy / md * 0.6; }

        if (n.reachable) {
          var pr = n.r + n.glow * 2.5;
          ctx.beginPath();
          ctx.arc(n.x, n.y, pr + 6 * n.glow, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(56,189,248,' + (0.10 + n.glow * 0.25) + ')';
          ctx.fill();
          ctx.beginPath();
          ctx.arc(n.x, n.y, pr, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(56,189,248,' + (0.5 + n.glow * 0.5) + ')';
          ctx.fill();
        } else {
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(120,160,220,0.3)';
          ctx.fill();
        }
      }
      requestAnimationFrame(frame);
    }

    window.addEventListener('mousemove', function (e) {
      var rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left; mouse.y = e.clientY - rect.top;
    });
    window.addEventListener('mouseout', function () { mouse.x = -9999; mouse.y = -9999; });
    window.addEventListener('resize', resize);
    resize();
    requestAnimationFrame(frame);
  }
})();
