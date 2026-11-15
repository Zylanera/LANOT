/* LANOT page script. Plain JS, no build step.
   Everything from the server is inserted with textContent, never as HTML. */
(function () {
  "use strict";

  var WORDS = { ok: "OK", warn: "Warning", bad: "Problem", unknown: "unknown", muted: "muted" };
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function icon(status) {
    var t = document.getElementById("ico-" + (WORDS[status] ? status : "unknown"));
    return t ? t.content.firstElementChild.cloneNode(true) : el("span");
  }

  function marker(status, word) {
    var m = el("span", "marker s-" + status);
    m.appendChild(icon(status));
    m.appendChild(el("span", "sr-only", (word || WORDS[status] || status) + ": "));
    return m;
  }

  function flash(node) {
    if (!node || reduceMotion) return;
    node.classList.remove("changed");
    void node.offsetWidth; // restart the animation
    node.classList.add("changed");
  }

  // -- overview ----------------------------------------------------------------
  function renderChain(chain, prev) {
    var ol = el("ol", "chain");
    ol.setAttribute("aria-label", "Path to the internet");
    chain.stations.forEach(function (s, i) {
      if (i > 0) {
        var seg = el("li", "seg" + (s.broken ? " broken" : s.status === "unknown" ? " dim" : ""));
        seg.setAttribute("aria-hidden", "true");
        if (s.broken) seg.appendChild(el("span", "gap", "✕"));
        ol.appendChild(seg);
      }
      var li = el("li", "station s-" + s.status + (s.broken ? " broken" : ""));
      li.setAttribute("data-station", s.id);
      li.appendChild(icon(s.status));
      var label = el("span", "st-label");
      label.appendChild(el("span", "st-name", s.name));
      label.appendChild(el("span", "sr-only", ": " + (WORDS[s.status] || s.status)));
      if (s.text) label.appendChild(el("span", "st-text", s.text));
      li.appendChild(label);
      if (prev && prev[s.id] && prev[s.id] !== s.status) flash(li);
      ol.appendChild(li);
    });
    return ol;
  }

  function renderRow(t, prev) {
    var li = el("li");
    var a = el("a", "row s-" + t.status);
    a.href = t.href;
    a.setAttribute("data-id", t.id);
    a.appendChild(marker(t.status));
    a.appendChild(el("span", "row-name", t.name));
    a.appendChild(el("span", "row-text", t.text));
    li.appendChild(a);
    if (prev && prev[t.id] && prev[t.id] !== t.status) flash(a);
    return li;
  }

  function renderIncident(i, withSummary) {
    var li = el("li");
    var a = el("a", "tl s-" + i.status);
    a.href = "/incident/" + encodeURIComponent(i.id);
    var title = el("span", "tl-title");
    title.appendChild(marker(i.status, i.open ? null : "Resolved"));
    title.appendChild(document.createTextNode(" "));
    title.appendChild(el("span", "tl-name", i.title));
    if (i.muted) {
      var tag = el("span", "mute-tag s-muted");
      tag.appendChild(icon("muted"));
      tag.appendChild(el("span", "word", "muted"));
      title.appendChild(document.createTextNode(" "));
      title.appendChild(tag);
    }
    a.appendChild(title);
    var sub = i.line + (i.times > 1 ? ", happened " + i.times + " times" : "");
    a.appendChild(el("span", "tl-sub", sub));
    if (withSummary && i.summary) a.appendChild(el("span", "tl-ai", i.summary));
    li.appendChild(a);
    return li;
  }

  function startOverview(root) {
    var updated = parseFloat(root.getAttribute("data-updated")) * 1000 || Date.now();
    var lastOk = Date.now();
    var failed = false;
    var stationState = {}, rowState = {};
    document.querySelectorAll("[data-station]").forEach(function (n) {
      var m = /s-(\w+)/.exec(n.className);
      stationState[n.getAttribute("data-station")] = m ? m[1] : "";
    });

    function tick() {
      var out = document.getElementById("updated");
      if (!out) return;
      if (failed) {
        out.textContent = "No connection to the LANOT server. Last checked " + ago(Date.now() - lastOk) + " ago.";
        return;
      }
      out.textContent = "Last checked " + ago(Date.now() - updated) + " ago";
    }

    function ago(ms) {
      var s = Math.max(0, Math.round(ms / 1000));
      if (s < 60) return s + " s";
      var m = Math.round(s / 60);
      return m < 60 ? m + " min" : Math.round(m / 60) + " h";
    }

    function apply(d) {
      var head = document.getElementById("headline");
      if (head.textContent !== d.headline) {
        head.textContent = d.headline;
        head.className = "hero-text s-" + d.status;
      }
      if (root.getAttribute("data-status") !== d.status) {
        root.setAttribute("data-status", d.status);
        flash(document.querySelector(".hero"));
      }
      var chainBox = document.getElementById("chain");
      chainBox.replaceChildren(renderChain(d.chain, stationState));
      stationState = {};
      d.chain.stations.forEach(function (s) { stationState[s.id] = s.status; });

      var devices = document.getElementById("devices");
      var rows = d.tiles.filter(function (t) { return t.id !== "internet" && t.id !== "router"; });
      devices.replaceChildren.apply(devices, rows.map(function (t) { return renderRow(t, rowState); }));
      rowState = {};
      rows.forEach(function (t) { rowState[t.id] = t.status; });

      var open = d.incidents.filter(function (i) { return i.open; });
      var done = d.incidents.filter(function (i) { return !i.open; });
      var list = document.getElementById("incidents");
      list.replaceChildren.apply(list, open.map(function (i) { return renderIncident(i, true); }));
      document.getElementById("no-incidents").hidden = open.length > 0;
      var recent = document.getElementById("recent");
      recent.replaceChildren.apply(recent, done.map(function (i) { return renderIncident(i, false); }));
      document.getElementById("recent-head").hidden = done.length === 0;
      updated = d.updated * 1000;
    }

    function poll() {
      fetch("/api/v1/ui/overview", { headers: { Accept: "application/json" }, cache: "no-store" })
        .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
        .then(function (d) { failed = false; lastOk = Date.now(); apply(d); tick(); })
        .catch(function () { failed = true; tick(); });
    }

    document.querySelectorAll("#devices .row").forEach(function (a) {
      var m = /s-(\w+)/.exec(a.className);
      rowState[a.getAttribute("data-id")] = m ? m[1] : "";
    });
    tick();
    setInterval(tick, 1000);
    setInterval(poll, 5000);
  }

  // -- device charts -------------------------------------------------------------
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  var PALETTE = ["--accent", "--warn", "--ok", "--bad", "--ink-soft"];

  function fmtTime(range) {
    var opts = range === "7d"
      ? { weekday: "short", day: "2-digit", month: "2-digit" }
      : { hour: "2-digit", minute: "2-digit" };
    var f = new Intl.DateTimeFormat(undefined, opts);  // the browser's own locale
    return function (u, vals) { return vals.map(function (v) { return f.format(new Date(v * 1000)); }); };
  }

  function summary(series, unit) {
    var parts = [];
    Object.keys(series).forEach(function (name) {
      var vals = series[name].filter(function (v) { return v !== null && v !== undefined; });
      if (!vals.length) return;
      var now = vals[vals.length - 1], max = Math.max.apply(null, vals), min = Math.min.apply(null, vals);
      var label = name === "" ? "" : name + ": ";
      parts.push(label + "now " + Math.round(now) + " " + unit + ", lowest " + Math.round(min) +
        " " + unit + ", highest " + Math.round(max) + " " + unit);
    });
    return parts.length ? parts.join(". ") + "." : "No measurements in this time span.";
  }

  function drawChart(fig, ts, series, unit, range) {
    var area = fig.querySelector(".chart-area");
    var sum = fig.querySelector(".chart-sum");
    sum.textContent = summary(series, unit);
    var names = Object.keys(series);
    if (!ts.length || !names.length || typeof uPlot === "undefined") return;
    var ink = cssVar("--ink-soft");
    var data = [ts].concat(names.map(function (n) { return series[n]; }));
    var opts = {
      width: Math.max(260, area.clientWidth),
      height: 180,
      scales: { x: { time: true }, y: unit === "%" ? { range: [0, 100] } : {} },
      axes: [
        { stroke: ink, grid: { show: false }, ticks: { show: false }, values: fmtTime(range), space: 70 },
        { stroke: ink, grid: { stroke: cssVar("--row-alt"), width: 1 },
          ticks: { show: false }, size: 44, values: function (u, v) { return v.map(function (x) { return x + " " + unit; }); } }
      ],
      legend: { show: names.length > 1 },
      cursor: { drag: { x: false, y: false } },
      series: [{ value: function (u, v) { return v == null ? "" : fmtTime(range)(u, [v])[0]; } }].concat(
        names.map(function (n, i) {
          return {
            label: n || fig.querySelector("figcaption").textContent,
            stroke: cssVar(PALETTE[i % PALETTE.length]),
            width: 2,
            spanGaps: false,
            value: function (u, v) { return v == null ? "–" : Math.round(v) + " " + unit; }
          };
        }))
    };
    area.replaceChildren();
    var plot = new uPlot(opts, data, area);
    window.addEventListener("resize", function () {
      plot.setSize({ width: Math.max(260, area.clientWidth), height: 180 });
    });
  }

  function startCharts(box) {
    var host = box.getAttribute("data-host");
    var range = box.getAttribute("data-range");
    fetch("/api/v1/ui/series/" + encodeURIComponent(host) + "?range=" + encodeURIComponent(range))
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        var defs = { cpu: [{ "": d.cpu }, "%"], mem: [{ "": d.mem }, "%"], temps: [d.temps, "°C"], disks: [d.disks, "%"] };
        box.querySelectorAll("[data-chart]").forEach(function (fig) {
          var def = defs[fig.getAttribute("data-chart")];
          drawChart(fig, d.ts, def[0], def[1], range);
        });
      })
      .catch(function () {
        box.querySelectorAll(".chart-sum").forEach(function (p) {
          p.textContent = "The history could not be loaded. Reload the page.";
        });
      });
  }

  // -- hamburger menu (progressive enhancement of <details>) ------------------------
  function startMenu(menu) {
    var btn = menu.querySelector("summary");
    var panel = menu.querySelector(".menu-panel");
    function sync() {
      btn.setAttribute("aria-expanded", menu.open ? "true" : "false");
      if (menu.open) {
        var first = panel.querySelector("a[aria-current]") || panel.querySelector("a");
        if (first) first.focus();
      }
    }
    menu.addEventListener("toggle", sync);
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && menu.open) {
        menu.open = false;
        btn.focus();
      }
    });
    panel.addEventListener("click", function (e) {
      if (e.target.closest("a")) menu.open = false;
    });
    document.addEventListener("click", function (e) {
      if (menu.open && !menu.contains(e.target)) menu.open = false;
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var menu = document.getElementById("menu");
    if (menu) startMenu(menu);
    var ov = document.getElementById("overview");
    if (ov) startOverview(ov);
    var charts = document.getElementById("charts");
    if (charts) startCharts(charts);
  });
})();
