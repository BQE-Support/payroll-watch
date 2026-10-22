/* Shared sign-in, data access and "who's viewing" for the hosted BQE boards (2026-10-21).
 *
 * Every board (Payroll Watch, Yodlee Watch, ...) is published under https://bqe-support.github.io/<repo>/,
 * which is ONE browser origin, so a board session saved here works on all of them: sign in once.
 *
 * Sign-in order:
 *   1. a saved board session that hasn't expired and lists this board;
 *   2. the RingCX Live View's own saved sign-in, if its RingCX token is still good (no new sign-in needed);
 *   3. RingCentral sign-in (PKCE, same RingCentral app as the Live View). The board's address must be on the
 *      app's redirect list. Local testing on localhost uses the dev server's /dev-token instead.
 * Steps 2 and 3 end with the "dash-auth" function, which checks the RingCX token and public.dash_access and
 * returns a signed 12-hour board session. RingCentral/RingCX tokens are never saved by this file.
 *
 * Usage (supabase-js 2.57.4 must be loaded first for presence):
 *   BQEBoard.start({ board: "payroll-watch", onReady: function (viewer) {...}, onSignIn: function (msg) {...} })
 *   BQEBoard.api("payroll-watch")            -> JSON from /functions/v1/payroll-watch (with the board session)
 *   BQEBoard.presence(function (people) {})  -> people viewing this board now: [{ name, initials, me }]
 *   BQEBoard.arrange(containerEl)            -> { toggle(), reset() }: movable [data-section] blocks, order saved per person
 *   BQEBoard.signIn() / BQEBoard.signOut()
 */
(function () {
  var CONFIG = {
    CLIENT_ID: "ZOg1i27x7SSdnbmeHGkLpT",   // RingCentral app "BQE RingCX Live View" (public identifier)
    RC_SERVER: "https://platform.ringcentral.com",
    RCX_SERVER: "https://ringcx.ringcentral.com",
    SUPABASE_URL: "https://qevavlolbygnjynyikru.supabase.co",
    SUPABASE_ANON_KEY: "sb_publishable_dvaKYnU6ab7qzSTWMUl00Q_hEVNOVDk",
    REDIRECT_URI: location.origin + location.pathname.replace(/index\.html$/, ""),
    STORE_KEY: "bqeBoards.session.v1",
    LIVE_VIEW_KEY: "rcxLiveView.session.v1",   // read only, never written
    PKCE_KEY: "bqeBoards.pkce.v1"
  };
  var IS_LOCAL = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);
  var opts = {}, session = null, pres = { client: null, channel: null, cb: null };

  function load(k) { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch (e) { return null; } }
  function save(k, v) { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  function form(o) { return Object.keys(o).map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(o[k]); }).join("&"); }
  function b64url(bytes) { var s = ""; bytes.forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function jwtExp(t) {
    try { var p = String(t).split(".")[1].replace(/-/g, "+").replace(/_/g, "/"); return (JSON.parse(atob(p + "===".slice((p.length + 3) % 4))).exp || 0) * 1000; } catch (e) { return 0; }
  }
  function initialsOf(n) { return String(n || "").split(/\s+/).filter(Boolean).map(function (p) { return p[0]; }).slice(0, 2).join("").toUpperCase(); }
  function usable(s) { return s && s.token && s.exp > Date.now() + 60000 && s.boards && s.boards[opts.board]; }

  // RingCX access token -> board session (dash-auth checks it and the access table).
  async function exchange(rcxAccess) {
    var r = await fetch(CONFIG.SUPABASE_URL + "/functions/v1/dash-auth", {
      method: "POST", headers: { apikey: CONFIG.SUPABASE_ANON_KEY, "x-rcx-token": rcxAccess }
    });
    var j = await r.json().catch(function () { return {}; });
    if (!r.ok) throw new Error(j.error || ("Sign-in failed (HTTP " + r.status + ")."));
    session = { token: j.token, exp: j.exp, agentId: j.agentId, name: j.name, boards: j.boards || {} };
    save(CONFIG.STORE_KEY, session);
    return session;
  }

  async function signIn() {
    if (IS_LOCAL) {   // local testing: the dev server mints a RingCX token from the admin credential
      var d = await fetch("/dev-token");
      if (!d.ok) throw new Error("Dev token endpoint failed: HTTP " + d.status);
      await exchange((await d.json()).accessToken);
      return ready();
    }
    var verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
    var challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    var state = b64url(crypto.getRandomValues(new Uint8Array(16)));
    try { sessionStorage.setItem(CONFIG.PKCE_KEY, JSON.stringify({ verifier: verifier, state: state })); } catch (e) {}
    location.href = CONFIG.RC_SERVER + "/restapi/oauth/authorize?" + form({
      response_type: "code", client_id: CONFIG.CLIENT_ID, redirect_uri: CONFIG.REDIRECT_URI,
      state: state, code_challenge: challenge, code_challenge_method: "S256"
    });
  }

  async function finishSignIn(code, state) {
    var pk = null; try { pk = JSON.parse(sessionStorage.getItem(CONFIG.PKCE_KEY)); } catch (e) {}
    history.replaceState(null, "", CONFIG.REDIRECT_URI);
    if (!pk || pk.state !== state) throw new Error("Sign-in state mismatch. Please try again.");
    var r = await fetch(CONFIG.RC_SERVER + "/restapi/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({ grant_type: "authorization_code", code: code, redirect_uri: CONFIG.REDIRECT_URI, client_id: CONFIG.CLIENT_ID, code_verifier: pk.verifier })
    });
    if (!r.ok) throw new Error("RingCentral sign-in failed (HTTP " + r.status + ").");
    var rc = await r.json();
    var x = await fetch(CONFIG.RCX_SERVER + "/api/auth/login/rc/accesstoken", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({ rcAccessToken: rc.access_token, rcTokenType: "Bearer" })
    });
    if (!x.ok) throw new Error("RingCentral sign-in worked, but RingCX refused it (HTTP " + x.status + "). Your RingCentral user may not have a RingCX account.");
    await exchange((await x.json()).accessToken);
  }

  function ready() {
    if (!usable(session)) {
      var msg = session && session.boards && !session.boards[opts.board] ? "This board isn't shared with you. Ask your support lead for access." : "";
      if (opts.onSignIn) opts.onSignIn(msg);
      return;
    }
    if (opts.onReady) opts.onReady({ agentId: session.agentId, name: session.name, role: session.boards[opts.board] });
  }

  async function start(o) {
    opts = o || {};
    try {
      var q = new URLSearchParams(location.search);
      if (q.get("code") && q.get("state")) { await finishSignIn(q.get("code"), q.get("state")); return ready(); }
      if (q.get("error")) { history.replaceState(null, "", CONFIG.REDIRECT_URI); throw new Error("RingCentral sign-in was cancelled (" + q.get("error") + ")."); }
      session = load(CONFIG.STORE_KEY);
      if (usable(session)) return ready();
      var live = load(CONFIG.LIVE_VIEW_KEY);
      if (live && live.rcxAccess && jwtExp(live.rcxAccess) > Date.now() + 30000) {
        try { await exchange(live.rcxAccess); return ready(); } catch (e) { /* fall through to a normal sign-in */ }
      }
      ready();
    } catch (e) {
      if (opts.onSignIn) opts.onSignIn(String(e.message || e));
    }
  }

  function signOut() {
    session = null; save(CONFIG.STORE_KEY, null);
    stopPresence();
    if (opts.onSignIn) opts.onSignIn("");
  }

  // GET (or POST with a body) to a board function with the board session. A 401 means the session ended.
  async function api(fn, init) {
    if (!usable(session)) { ready(); throw new Error("Not signed in."); }
    init = init || {};
    var h = Object.assign({ apikey: CONFIG.SUPABASE_ANON_KEY, "x-dash-token": session.token }, init.headers || {});
    if (init.body && typeof init.body !== "string") { h["Content-Type"] = "application/json"; init.body = JSON.stringify(init.body); }
    var r = await fetch(CONFIG.SUPABASE_URL + "/functions/v1/" + fn, Object.assign({}, init, { headers: h }));
    if (r.status === 304) return null;
    var j = await r.json().catch(function () { return {}; });
    if (r.status === 401) { signOut(); throw new Error(j.error || "Your session expired."); }
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  }

  // Who's viewing this board right now (Supabase Realtime presence, one channel per board, no tables).
  // Only names travel on the channel; all data goes through the access-checked functions.
  function presence(cb) {
    pres.cb = cb;
    if (pres.channel || !window.supabase || !usable(session)) { if (cb) cb([{ name: session ? session.name : "", initials: initialsOf(session && session.name), me: true }]); return; }
    try {
      var me = session.agentId + ":" + Math.random().toString(36).slice(2, 8);   // one key per open tab
      pres.client = window.supabase.createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY, { auth: { persistSession: false } });
      pres.channel = pres.client.channel("board:" + opts.board, { config: { presence: { key: me } } });
      pres.channel.on("presence", { event: "sync" }, function () {
        var st = pres.channel.presenceState(), seen = {}, out = [];
        Object.keys(st).forEach(function (k) {
          (st[k] || []).forEach(function (p) {
            if (!p.name || seen[p.id]) return;
            seen[p.id] = 1;
            out.push({ name: p.name, initials: initialsOf(p.name), me: p.id === session.agentId });
          });
        });
        out.sort(function (a, b) { return (b.me - a.me) || a.name.localeCompare(b.name); });
        if (pres.cb) pres.cb(out);
      }).subscribe(function (status) {
        if (status === "SUBSCRIBED") pres.channel.track({ id: session.agentId, name: session.name, since: Date.now() });
      });
    } catch (e) { pres.channel = null; }
  }
  function stopPresence() {
    try { if (pres.channel) { pres.channel.untrack(); pres.client.removeChannel(pres.channel); } } catch (e) {}
    pres.channel = null;
  }
  addEventListener("pagehide", stopPresence);

  // ---- Arrange: each person moves sections around; the order is saved per person per board on the server
  // (public.dash_layouts through dash-auth), so it follows them to any device (2026-10-21).
  // The board marks each movable block as a direct child of one container with data-section="<id>" (and,
  // optionally, data-section-label). Sections must sit together in the container; anything before or after
  // them (the heading, the footer) stays put. Sections missing from a saved order keep their default place.
  var arr = { box: null, on: false, defaults: [], dragged: null, saveTimer: null };
  var ARRANGE_CSS =
    ".bqe-arranging [data-section]{outline:2px dashed var(--border,#ccc);outline-offset:6px;border-radius:10px}" +
    ".bqe-arranging [data-section].bqe-drop-before{box-shadow:0 -4px 0 var(--accent,#3454D1)}" +
    ".bqe-arranging [data-section].bqe-drop-after{box-shadow:0 4px 0 var(--accent,#3454D1)}" +
    ".bqe-arrange-bar{display:flex;align-items:center;gap:8px;margin-bottom:8px;padding:6px 10px;border-radius:8px;" +
    "background:var(--accent-soft,#E7EBFB);color:var(--accent,#3454D1);font:600 12.5px -apple-system,Segoe UI,Roboto,Arial,sans-serif;cursor:grab;user-select:none}" +
    ".bqe-arrange-bar:active{cursor:grabbing}.bqe-arrange-bar .bqe-grip{font-size:15px;letter-spacing:-2px}" +
    ".bqe-arrange-bar span.bqe-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" +
    ".bqe-arrange-bar button{border:1px solid currentColor;background:transparent;color:inherit;border-radius:6px;padding:2px 9px;font:inherit;cursor:pointer}";
  function sectionEls() { return Array.prototype.filter.call(arr.box.children, function (el) { return el.hasAttribute("data-section"); }); }
  function idOf(el) { return el.getAttribute("data-section"); }
  function labelOf(el) {
    if (el.getAttribute("data-section-label")) return el.getAttribute("data-section-label");
    var h = el.querySelector("h1, h2, summary"); return h ? h.textContent.trim().replace(/\s+/g, " ").slice(0, 60) : idOf(el);
  }
  function placeInOrder(order) {
    var els = sectionEls(), byId = {}; els.forEach(function (el) { byId[idOf(el)] = el; });
    var ids = (order || []).filter(function (id, i, a) { return byId[id] && a.indexOf(id) === i; });
    arr.defaults.forEach(function (id, i) { if (byId[id] && ids.indexOf(id) < 0) ids.splice(Math.min(i, ids.length), 0, id); });
    var end = els[els.length - 1].nextSibling;
    ids.forEach(function (id) { arr.box.insertBefore(byId[id], end); });
  }
  function saveOrder(order) {
    clearTimeout(arr.saveTimer);
    arr.saveTimer = setTimeout(function () {
      api("dash-auth", { method: "POST", body: { action: "layout", board: opts.board, order: order } }).catch(function () {});
    }, 400);
  }
  function currentOrder() { return sectionEls().map(idOf); }
  function moved() { saveOrder(currentOrder()); if (arr.onChange) arr.onChange(); }
  function addBars() {
    sectionEls().forEach(function (el) {
      if (el.querySelector(":scope > .bqe-arrange-bar")) return;
      var bar = document.createElement("div");
      bar.className = "bqe-arrange-bar"; bar.draggable = true;
      bar.innerHTML = '<span class="bqe-grip" aria-hidden="true">⠇⠇</span><span class="bqe-name"></span>' +
        '<button type="button" data-bqe-move="-1" aria-label="Move up">↑</button><button type="button" data-bqe-move="1" aria-label="Move down">↓</button>';
      bar.querySelector(".bqe-name").textContent = labelOf(el);
      el.insertBefore(bar, el.firstChild);
    });
  }
  function removeBars() { Array.prototype.forEach.call(arr.box.querySelectorAll(".bqe-arrange-bar"), function (b) { b.remove(); }); }
  function clearDrop() { sectionEls().forEach(function (el) { el.classList.remove("bqe-drop-before", "bqe-drop-after"); }); }
  function wireArrange() {
    arr.box.addEventListener("click", function (e) {
      var b = e.target.closest && e.target.closest("[data-bqe-move]"); if (!b || !arr.on) return;
      var el = b.closest("[data-section]"), els = sectionEls(), i = els.indexOf(el), d = +b.getAttribute("data-bqe-move");
      var other = els[i + d]; if (!other) return;
      if (d < 0) arr.box.insertBefore(el, other); else arr.box.insertBefore(other, el);
      el.scrollIntoView({ block: "nearest" }); moved();
    });
    arr.box.addEventListener("dragstart", function (e) {
      var bar = e.target.closest && e.target.closest(".bqe-arrange-bar"); if (!bar || !arr.on) return;
      arr.dragged = bar.closest("[data-section]"); e.dataTransfer.effectAllowed = "move";
      try { e.dataTransfer.setData("text/plain", idOf(arr.dragged)); } catch (x) {}
    });
    arr.box.addEventListener("dragover", function (e) {
      if (!arr.dragged) return;
      var el = e.target.closest && e.target.closest("[data-section]"); if (!el || el.parentNode !== arr.box || el === arr.dragged) return;
      e.preventDefault(); clearDrop();
      var r = el.getBoundingClientRect(); el.classList.add(e.clientY < r.top + r.height / 2 ? "bqe-drop-before" : "bqe-drop-after");
    });
    arr.box.addEventListener("drop", function (e) {
      if (!arr.dragged) return;
      var el = e.target.closest && e.target.closest("[data-section]");
      if (el && el.parentNode === arr.box && el !== arr.dragged) {
        e.preventDefault();
        arr.box.insertBefore(arr.dragged, el.classList.contains("bqe-drop-before") ? el : el.nextSibling);
        moved();
      }
      clearDrop(); arr.dragged = null;
    });
    arr.box.addEventListener("dragend", function () { clearDrop(); arr.dragged = null; });
  }
  // Sets up a board's sections and applies the person's saved order. Returns controls for the page's buttons.
  function arrange(box, onChange) {
    arr.box = box; arr.onChange = onChange;
    arr.defaults = sectionEls().map(idOf);
    if (!document.getElementById("bqe-arrange-css")) {
      var st = document.createElement("style"); st.id = "bqe-arrange-css"; st.textContent = ARRANGE_CSS; document.head.appendChild(st);
    }
    wireArrange();
    api("dash-auth?board=" + encodeURIComponent(opts.board)).then(function (j) {
      if (j && j.layout && j.layout.order) placeInOrder(j.layout.order);
    }).catch(function () {});
    return {
      toggle: function () { arr.on = !arr.on; box.classList.toggle("bqe-arranging", arr.on); if (arr.on) addBars(); else removeBars(); return arr.on; },
      reset: function () { placeInOrder(arr.defaults.slice()); saveOrder(null); if (arr.onChange) arr.onChange(); },
      isOn: function () { return arr.on; }
    };
  }

  window.BQEBoard = { start: start, signIn: signIn, signOut: signOut, api: api, presence: presence, arrange: arrange, initialsOf: initialsOf, config: CONFIG };
})();
