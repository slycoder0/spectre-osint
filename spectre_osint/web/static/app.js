(function () {
  "use strict";

  var LANG_KEY = "spectre_lang";
  var THEME_KEY = "spectre_theme";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function setCookie(name, value) {
    document.cookie = name + "=" + encodeURIComponent(value) + "; Path=/; SameSite=Lax; Max-Age=31536000";
  }

  function persist(name, value) {
    try {
      localStorage.setItem(name, value);
    } catch (err) {
      /* ignore quota */
    }
    setCookie(name, value);
  }

  function initThemeToggle() {
    var toggle = document.querySelector("[data-theme-toggle]");
    if (!toggle) return;
    toggle.addEventListener("click", function (event) {
      event.preventDefault();
      var html = document.documentElement;
      var next = html.getAttribute("data-theme") === "light" ? "dark" : "light";
      html.setAttribute("data-theme", next);
      persist(THEME_KEY, next);
      toggle.setAttribute("title", next === "dark" ? "Light" : "Dark");
    });
  }

  function syncPrefs() {
    var html = document.documentElement;
    persist(THEME_KEY, html.getAttribute("data-theme") || "dark");
    persist(LANG_KEY, html.getAttribute("lang") === "pt-BR" ? "pt-BR" : "en");
  }

  function initMenu() {
    var btn = document.querySelector("[data-menu-toggle]");
    var bar = document.querySelector("[data-topbar]");
    if (!btn || !bar) return;
    btn.addEventListener("click", function () {
      bar.classList.toggle("is-open");
    });
  }

  function detectType(value) {
    var v = (value || "").trim();
    if (!v) return "";
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return "EMAIL";
    if (/^https?:\/\//i.test(v) || /^www\./i.test(v)) return "URL";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.indexOf(":") >= 0 && /[0-9a-f:]{2,}/i.test(v)) return "IP";
    if (/^[0-9a-f]{32}$/i.test(v) || /^[0-9a-f]{40}$/i.test(v) || /^[0-9a-f]{64}$/i.test(v)) return "HASH";
    if (v.indexOf(".") >= 0 && !/\s/.test(v) && v.indexOf("@") < 0) return "DOMAIN";
    if (/^[a-zA-Z0-9._-]{2,}$/.test(v)) return "USERNAME";
    return "";
  }

  function initCollectForm() {
    document.querySelectorAll("[data-collect-form]").forEach(function (form) {
      var select = form.querySelector("[data-existing-case]");
      var wrap = form.querySelector("[data-existing-wrap]");
      var radios = form.querySelectorAll('input[name="mode"]');
      function sync() {
        var existing = form.querySelector('input[name="mode"][value="existing"]');
        var on = Boolean(existing && existing.checked);
        if (select) select.disabled = !on;
        if (wrap) wrap.classList.toggle("is-open", on);
      }
      radios.forEach(function (radio) {
        radio.addEventListener("change", sync);
      });
      sync();
      form.addEventListener("submit", function () {
        var btn = form.querySelector(".btn-primary");
        if (btn) {
          btn.classList.add("is-loading");
          btn.setAttribute("aria-busy", "true");
        }
      });
      var target = form.querySelector("[data-target-input]");
      var pill = form.querySelector("[data-detected-type]");
      if (target && pill) {
        target.addEventListener("input", function () {
          var kind = detectType(target.value);
          pill.textContent = kind || "";
          pill.classList.toggle("is-on", Boolean(kind));
        });
      }
    });
  }

  function addAliasChip(list, value) {
    var text = (value || "").replace(/^@/, "").trim();
    if (!text) return;
    var exists = false;
    list.querySelectorAll('input[name="alias"]').forEach(function (input) {
      if (input.value === text) exists = true;
    });
    if (exists) return;
    var chip = document.createElement("span");
    chip.className = "chip";
    chip.innerHTML = "<span></span><button type=\"button\" data-remove-alias aria-label=\"Remove\">×</button><input type=\"hidden\" name=\"alias\" />";
    chip.querySelector("span").textContent = "@" + text;
    chip.querySelector("input").value = text;
    list.appendChild(chip);
  }

  function initAliasFields() {
    var root = document.querySelector("[data-alias-chips]");
    if (!root) return;
    var list = root.querySelector("[data-chip-list]");
    var input = root.querySelector("[data-chip-input]");
    var add = document.querySelector("[data-add-alias]");
    function commit() {
      if (!input) return;
      addAliasChip(list, input.value);
      input.value = "";
    }
    if (add) add.addEventListener("click", commit);
    if (input) {
      input.addEventListener("keydown", function (evt) {
        if (evt.key === "Enter" || evt.key === ",") {
          evt.preventDefault();
          commit();
        } else if ((evt.key === "Backspace" || evt.key === "Delete") && !input.value) {
          var chips = list.querySelectorAll(".chip");
          if (chips.length) chips[chips.length - 1].remove();
        }
      });
      input.addEventListener("blur", commit);
    }
    root.addEventListener("click", function (evt) {
      var btn = evt.target.closest("[data-remove-alias]");
      if (btn) {
        var chip = btn.closest(".chip");
        if (chip) chip.remove();
      }
    });
  }

  function initCopy() {
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy") || "";
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          var prev = btn.textContent;
          btn.textContent = "OK";
          setTimeout(function () {
            btn.textContent = prev;
          }, 900);
        });
      });
    });
  }

  var drawer = {
    root: null,
    title: null,
    body: null,
    lastFocus: null,
    open: function (title, html) {
      if (!this.root) return;
      this.lastFocus = document.activeElement;
      this.title.textContent = title || "";
      if (typeof html === "string") this.body.innerHTML = html;
      else {
        this.body.innerHTML = "";
        if (html) this.body.appendChild(html);
      }
      this.root.hidden = false;
      var close = this.root.querySelector(".drawer-close");
      if (close) close.focus();
      document.addEventListener("keydown", this._onKey);
    },
    close: function () {
      if (!this.root) return;
      this.root.hidden = true;
      this.body.innerHTML = "";
      document.removeEventListener("keydown", this._onKey);
      if (this.lastFocus && this.lastFocus.focus) this.lastFocus.focus();
    }
  };
  drawer._onKey = function (evt) {
    if (evt.key === "Escape") drawer.close();
  };

  function initDrawer() {
    drawer.root = document.querySelector("[data-drawer]");
    if (!drawer.root) return;
    drawer.title = drawer.root.querySelector("[data-drawer-title]");
    drawer.body = drawer.root.querySelector("[data-drawer-body]");
    drawer.root.querySelectorAll("[data-drawer-close]").forEach(function (el) {
      el.addEventListener("click", function () { drawer.close(); });
    });
    document.addEventListener("click", function (evt) {
      var btn = evt.target.closest("[data-drawer-src]");
      if (!btn) return;
      var id = btn.getAttribute("data-drawer-src");
      var tpl = id ? document.getElementById(id) : null;
      if (!tpl) return;
      var clone = tpl.content.cloneNode(true);
      var heading = clone.querySelector("h3");
      drawer.open(heading ? heading.textContent : "", clone);
    });
    window.SpectreDrawer = drawer;
  }

  function pollJob() {
    var stage = document.querySelector("[data-job-id]");
    if (!stage) return;
    var jobId = stage.getAttribute("data-job-id");
    var status = stage.getAttribute("data-job-status");
    if (!jobId) return;
    if (status === "complete") {
      var caseId = stage.getAttribute("data-case-id");
      if (caseId) window.location.href = "/investigations/" + caseId;
      return;
    }
    if (status === "failed") return;

    var PHASES = ["catalog", "mentions", "search", "discovery", "correlation", "scoring", "report"];
    var phaseMap = {
      "loading_catalog": "catalog",
      "initializing": "catalog",
      "collecting": "catalog",
      "reporting": "report",
      "correlating": "correlation"
    };

    var timer = setInterval(function () {
      fetch("/jobs/" + jobId, { headers: { Accept: "application/json" } })
        .then(function (res) { return res.ok ? res.json() : null; })
        .then(function (snap) {
          if (!snap) return;

          stage.setAttribute("data-job-status", snap.status || "running");
          stage.setAttribute("data-job-phase", snap.phase || "");
          stage.setAttribute("data-job-state", snap.state || "running");

          if (snap.status === "complete" && snap.case_id) {
            stage.classList.add("is-complete");
            clearInterval(timer);
            setTimeout(function () {
              window.location.href = "/investigations/" + snap.case_id;
            }, 450);
            return;
          } else if (snap.status === "failed") {
            clearInterval(timer);
            window.location.reload();
            return;
          }

          var banner = stage.querySelector("[data-status-banner]");
          if (banner && snap.phase) {
            var rawPhase = snap.phase;
            var normalizedPhase = phaseMap[rawPhase] || rawPhase;
            var phaseItem = stage.querySelector('[data-phase-item="' + normalizedPhase + '"]');
            if (phaseItem) {
              banner.textContent = phaseItem.textContent.replace(/^[◌✓○]\s*/, "");
            }
          }

          var fill = stage.querySelector(".activity-fill");
          var counter = stage.querySelector("[data-progress-counter]");
          if (snap.progress_kind === "determinate" && snap.total) {
            if (fill) {
              fill.className = "activity-fill determinate";
              fill.style.setProperty("--done", snap.done || 0);
              fill.style.setProperty("--total", snap.total || 1);
            }
            if (counter) {
              counter.innerHTML = '<p class="source-count">' + (snap.done || 0) + ' of ' + snap.total + ' sources processed</p>';
            }
          } else {
            if (fill) {
              fill.className = "activity-fill indeterminate";
              fill.style.removeProperty("--done");
              fill.style.removeProperty("--total");
            }
          }

          var currentPhase = phaseMap[snap.phase] || snap.phase;
          var curIdx = PHASES.indexOf(currentPhase);
          if (curIdx >= 0) {
            PHASES.forEach(function (ph, idx) {
              var li = stage.querySelector('[data-phase-item="' + ph + '"]');
              if (!li) return;
              var label = li.textContent.replace(/^[◌✓○]\s*/, "");
              if (idx < curIdx) {
                li.className = "done";
                li.textContent = "✓ " + label;
              } else if (idx === curIdx) {
                li.className = "current";
                li.textContent = "◌ " + label;
              } else {
                li.className = "";
                li.textContent = "○ " + label;
              }
            });
          }

          var degradedLog = stage.querySelector("[data-degraded-log]");
          if (degradedLog && snap.degraded_sources && snap.degraded_sources.length) {
            degradedLog.hidden = false;
            degradedLog.innerHTML = snap.degraded_sources.map(function (d) {
              return "<li>⚠ " + (d.message || d.provider + " unavailable; continuing") + "</li>";
            }).join("");
          }
        })
        .catch(function () { /* keep meta-refresh fallback */ });
    }, 700);
  }

  function initMentionTabs() {
    var tabs = document.querySelectorAll("[data-mention-tab]");
    if (!tabs.length) return;
    function apply(name) {
      tabs.forEach(function (tab) {
        tab.setAttribute("aria-selected", tab.getAttribute("data-mention-tab") === name ? "true" : "false");
      });
      document.querySelectorAll(".mention-card[data-relevance]").forEach(function (card) {
        card.classList.toggle("is-hidden", card.getAttribute("data-relevance") !== name);
      });
    }
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        apply(tab.getAttribute("data-mention-tab") || "DIRECT");
      });
    });
    apply("DIRECT");
    document.querySelectorAll(".mention-card").forEach(function (card) {
      card.addEventListener("click", function (evt) {
        if (evt.target.closest("a, button")) return;
        card.classList.toggle("is-open");
        var more = card.querySelector(".mention-more");
        if (more) more.hidden = !card.classList.contains("is-open");
      });
    });
  }

  function initFootprint() {
    var input = document.querySelector("[data-footprint-search]");
    var rows = document.querySelectorAll(".foot-row");
    var current = "FOUND";
    function matchFilter(status) {
      if (current === "ALL") return true;
      if (current === "FOUND") return status === "CONFIRMED" || status === "LIKELY";
      if (current === "ISSUES") {
        return ["BLOCKED", "LOGIN_REQUIRED", "RATE_LIMITED", "PROVIDER_UNAVAILABLE", "SESSION_EXPIRED", "CHALLENGE_REQUIRED", "CAPTCHA_REQUIRED", "TEMPORARILY_LIMITED", "OAUTH_BROWSER_REJECTED"].indexOf(status) >= 0;
      }
      return status === current;
    }
    function apply() {
      var q = input ? (input.value || "").toLowerCase() : "";
      rows.forEach(function (row) {
        var hay = (row.getAttribute("data-platform") || "").toLowerCase();
        var status = row.getAttribute("data-status") || "";
        var show = matchFilter(status) && (!q || hay.indexOf(q) !== -1);
        row.classList.toggle("is-hidden", !show);
      });
    }
    if (input) input.addEventListener("input", apply);
    document.querySelectorAll("[data-foot-filter]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        current = btn.getAttribute("data-foot-filter") || "FOUND";
        document.querySelectorAll("[data-foot-filter]").forEach(function (el) {
          el.classList.toggle("active", el === btn);
        });
        apply();
      });
    });
    apply();
  }

  function initScrollSpy() {
    var links = document.querySelectorAll("[data-nav-sec]");
    if (!links.length) return;
    var ids = [];
    links.forEach(function (link) {
      ids.push(link.getAttribute("data-nav-sec"));
      link.addEventListener("click", function (evt) {
        var id = link.getAttribute("data-nav-sec");
        var el = id ? document.getElementById(id) : null;
        if (!el) return;
        evt.preventDefault();
        el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      });
    });
    function tick() {
      var active = ids[0];
      var mark = 120;
      ids.forEach(function (id) {
        var el = document.getElementById(id);
        if (!el) return;
        var top = el.getBoundingClientRect().top;
        if (top <= mark) active = id;
      });
      links.forEach(function (link) {
        link.classList.toggle("active", link.getAttribute("data-nav-sec") === active);
      });
    }
    window.addEventListener("scroll", tick, { passive: true });
    tick();
  }

  function initCountUp() {
    if (reduce) return;
    document.querySelectorAll("[data-count]").forEach(function (el) {
      var end = parseFloat(el.getAttribute("data-count") || "0");
      if (!isFinite(end)) return;
      var start = 0;
      var t0 = null;
      var suffix = "";
      var rest = el.innerHTML.replace(/^[\d.]+/, "");
      suffix = rest;
      function frame(ts) {
        if (!t0) t0 = ts;
        var p = Math.min(1, (ts - t0) / 700);
        var eased = 1 - Math.pow(1 - p, 3);
        var val = Math.round(start + (end - start) * eased);
        el.innerHTML = String(val) + suffix;
        if (p < 1) requestAnimationFrame(frame);
      }
      requestAnimationFrame(frame);
    });
  }

  function initInvestigations() {
    var grid = document.querySelector("[data-inv-grid]");
    if (!grid) return;
    var search = document.querySelector("[data-inv-search]");
    var sort = document.querySelector("[data-inv-sort]");
    var cards = Array.prototype.slice.call(grid.querySelectorAll(".inv-card"));
    function apply() {
      var q = search ? (search.value || "").toLowerCase() : "";
      cards.forEach(function (card) {
        var hay = ((card.getAttribute("data-name") || "") + " " + (card.getAttribute("data-target") || "")).toLowerCase();
        card.classList.toggle("is-hidden", Boolean(q) && hay.indexOf(q) === -1);
      });
      var key = sort ? sort.value : "updated";
      cards.sort(function (a, b) {
        if (key === "name") return (a.getAttribute("data-name") || "").localeCompare(b.getAttribute("data-name") || "");
        return String(b.getAttribute("data-updated") || "").localeCompare(String(a.getAttribute("data-updated") || ""));
      });
      cards.forEach(function (card) { grid.appendChild(card); });
    }
    if (search) search.addEventListener("input", apply);
    if (sort) sort.addEventListener("change", apply);
    document.querySelectorAll('input[name="inv-view"]').forEach(function (radio) {
      radio.addEventListener("change", function () {
        grid.classList.toggle("is-grid", radio.value === "grid" && radio.checked);
      });
    });
  }

  function initEntityView() {
    var visual = document.querySelector("[data-ent-visual]");
    var table = document.querySelector("[data-ent-table]");
    if (!visual || !table) return;
    document.querySelectorAll('input[name="ent-view"]').forEach(function (radio) {
      radio.addEventListener("change", function () {
        var tableOn = radio.value === "table" && radio.checked;
        visual.hidden = tableOn;
        table.hidden = !tableOn;
      });
    });
  }

  function initTooltips() {
    var layer = document.querySelector("[data-tooltip-layer]");
    if (!layer) return;
    var timer = null;
    function hide() {
      layer.classList.remove("is-on");
      layer.hidden = true;
    }
    document.addEventListener("mouseover", function (evt) {
      var el = evt.target.closest("[data-tip], .badge, [title]");
      if (!el || el.closest(".drawer-root")) return;
      var text = el.getAttribute("data-tip") || el.getAttribute("title");
      if (!text) return;
      if (el.getAttribute("title")) el.setAttribute("data-native-title", el.getAttribute("title"));
      el.removeAttribute("title");
      clearTimeout(timer);
      timer = setTimeout(function () {
        layer.textContent = text;
        layer.hidden = false;
        var rect = el.getBoundingClientRect();
        layer.style.left = Math.min(window.innerWidth - 280, rect.left) + "px";
        layer.style.top = (rect.bottom + 8) + "px";
        layer.classList.add("is-on");
      }, 280);
    });
    document.addEventListener("mouseout", function (evt) {
      var el = evt.target.closest("[data-tip], .badge, [data-native-title]");
      if (!el) return;
      clearTimeout(timer);
      hide();
      var native = el.getAttribute("data-native-title");
      if (native) el.setAttribute("title", native);
    });
  }

  function initMediaFallback() {
    document.querySelectorAll("img[data-fallback]").forEach(function (img) {
      img.addEventListener("error", function () {
        var letter = (img.getAttribute("data-fallback") || "?").slice(0, 1).toUpperCase();
        var ph = document.createElement(img.classList.contains("pc-ava") ? "span" : "div");
        ph.className = img.className + (img.className.indexOf("ph") >= 0 ? "" : " ph");
        ph.setAttribute("aria-hidden", "true");
        ph.textContent = letter;
        img.replaceWith(ph);
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    syncPrefs();
    initThemeToggle();
    initMenu();
    initCollectForm();
    initCopy();
    pollJob();
    initAliasFields();
    initMentionTabs();
    initFootprint();
    initDrawer();
    initScrollSpy();
    initCountUp();
    initInvestigations();
    initEntityView();
    initTooltips();
    initMediaFallback();
  });
})();
