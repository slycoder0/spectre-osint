(function () {
  "use strict";

  function parseData() {
    var holder = document.getElementById("graph-data");
    if (!holder) return null;
    try {
      return JSON.parse(holder.textContent || "{}");
    } catch (err) {
      return null;
    }
  }

  function shapePath(shape, x, y) {
    var r = shape === "circle-lg" ? 22 : shape === "circle-sm" ? 8 : 13;
    if (shape === "square") {
      return { type: "rect", x: x - 11, y: y - 11, w: 22, h: 22 };
    }
    if (shape === "diamond") {
      return { type: "poly", points: [x, y - 13, x + 12, y, x, y + 13, x - 12, y] };
    }
    if (shape === "hexagon") {
      return {
        type: "poly",
        points: [x + 13, y, x + 7, y + 11, x - 7, y + 11, x - 13, y, x - 7, y - 11, x + 7, y - 11]
      };
    }
    return { type: "circle", x: x, y: y, r: r, dashed: shape === "dashed-circle" };
  }

  function text(el, value) {
    el.textContent = value == null ? "" : String(value);
    return el;
  }

  function nodeDrawer(node) {
    var wrap = document.createElement("div");
    function block(label, value) {
      if (!value) return;
      var ev = document.createElement("div");
      ev.className = "ev-block";
      var k = document.createElement("div");
      k.className = "k";
      text(k, label);
      var v = document.createElement("div");
      v.className = "v";
      text(v, value);
      ev.appendChild(k);
      ev.appendChild(v);
      wrap.appendChild(ev);
    }
    block("Type", node.type);
    block("Kind", node.kind);
    block("Username", node.username);
    block("Status", node.status);
    block("Confidence", node.confidence);
    block("Access", node.access);
    block("Relations", (node.relations || []).join(", "));
    block("Domains", (node.domains || []).join(", "));
    (node.urls || []).forEach(function (u) {
      var ev = document.createElement("div");
      ev.className = "ev-block";
      var k = document.createElement("div");
      k.className = "k";
      text(k, "URL");
      var a = document.createElement("a");
      a.className = "ext";
      a.href = u;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      text(a, u);
      ev.appendChild(k);
      ev.appendChild(a);
      wrap.appendChild(ev);
    });
    (node.evidence || []).forEach(function (item) {
      block("Evidence", item);
    });
    if (node.full_label) block("Label", node.full_label);
    return wrap;
  }

  function initGraph() {
    var svg = document.getElementById("relationship-graph");
    var data = parseData();
    if (!svg || !data) return;
    var nodes = (data.nodes || []).map(function (n, i) {
      return Object.assign({ x: 0, y: 0, index: i }, n);
    });
    var edges = data.edges || [];
    if (!nodes.length) return;

    var wrap = svg.parentElement;
    var w = Math.max((wrap && wrap.clientWidth) || 720, 480);
    var h = Math.max(svg.clientHeight || 560, 520);
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    svg.setAttribute("width", String(w));
    svg.setAttribute("height", String(h));
    var ns = "http://www.w3.org/2000/svg";
    var view = { x: 0, y: 0, k: 1 };
    var selected = null;
    var hovered = null;
    var dragging = null;
    var panning = null;
    var DRAG_THRESHOLD = 5;
    var showLabels = false;
    var filters = Object.assign({}, data.filters || {});
    filters.OPERATOR_PROVIDED_ALIAS = true;

    function el(name, attrs) {
      var node = document.createElementNS(ns, name);
      Object.keys(attrs || {}).forEach(function (key) {
        node.setAttribute(key, attrs[key]);
      });
      return node;
    }

    function groupOn(node) {
      if (node.kind === "target") return true;
      var group = node.group || node.kind || "other";
      if (group === "target") return true;
      return filters[group] !== false;
    }

    function visibleEdge(edge) {
      var rels = edge.relations && edge.relations.length ? edge.relations : [edge.relation];
      return rels.some(function (rel) {
        if (filters[rel] === false) return false;
        if (filters[rel] === true) return true;
        return edge.default_on !== false && ["HAS_PROFILE", "LINKS_TO", "IDENTITY_LINK", "OPERATOR_PROVIDED_ALIAS"].indexOf(rel) >= 0;
      });
    }

    function nodeHasVisibleLink(node) {
      if (node.kind === "target") return true;
      return edges.some(function (edge) {
        if (!visibleEdge(edge)) return false;
        return edge.from === node.id || edge.to === node.id;
      });
    }

    function visibleNode(node) {
      if (!groupOn(node)) return false;
      return nodeHasVisibleLink(node);
    }

    function ringPlace(arr, cx, cy, radius, start) {
      arr.forEach(function (node, index) {
        var angle = ((Math.PI * 2 * index) / Math.max(arr.length, 1)) + start;
        node.x = cx + radius * Math.cos(angle);
        node.y = cy + radius * Math.sin(angle);
      });
    }

    function layoutConcentric() {
      var cx = w / 2;
      var cy = h / 2;
      var vis = nodes.filter(groupOn);
      var target = vis.find(function (n) { return n.kind === "target"; }) || vis[0] || nodes[0];
      var aliases = vis.filter(function (n) { return n.id !== target.id && (n.alias || n.kind === "username"); });
      var profiles = vis.filter(function (n) { return n.kind === "profile"; });
      var rest = vis.filter(function (n) {
        return n.id !== target.id && aliases.indexOf(n) < 0 && profiles.indexOf(n) < 0;
      });
      target.x = cx;
      target.y = cy;
      var span = Math.min(w, h);
      ringPlace(aliases, cx, cy, span * 0.24, 0);
      ringPlace(profiles, cx, cy, span * 0.38, 0.35);
      ringPlace(rest, cx, cy, span * 0.46, 1.1);
    }

    layoutConcentric();

    function connectedIds(id) {
      var set = {};
      set[id] = true;
      edges.forEach(function (edge) {
        if (!visibleEdge(edge)) return;
        if (edge.from === id) set[edge.to] = true;
        if (edge.to === id) set[edge.from] = true;
      });
      return set;
    }

    function screenToWorld(evt) {
      var rect = svg.getBoundingClientRect();
      var sx = ((evt.clientX - rect.left) / rect.width) * w;
      var sy = ((evt.clientY - rect.top) / rect.height) * h;
      return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k };
    }

    function render() {
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      var root = el("g", {
        transform: "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")"
      });
      svg.appendChild(root);
      var focus = selected || hovered;
      var linked = focus ? connectedIds(focus) : null;
      edges.forEach(function (edge) {
        if (!visibleEdge(edge)) return;
        var a = nodes.find(function (n) { return n.id === edge.from; });
        var b = nodes.find(function (n) { return n.id === edge.to; });
        if (!a || !b || !visibleNode(a) || !visibleNode(b)) return;
        var fade = linked && !linked[a.id] ? " is-faded" : "";
        var hi = focus && (edge.from === focus || edge.to === focus);
        var rels = edge.relations || [edge.relation];
        var style = "";
        if (rels.indexOf("IDENTITY_LINK") >= 0) style += " edge-identity";
        if (rels.indexOf("OPERATOR_PROVIDED_ALIAS") >= 0 || rels.indexOf("OPERATOR_PROVIDED_INPUT") >= 0) style += " edge-operator";
        var line = el("line", {
          x1: String(a.x), y1: String(a.y), x2: String(b.x), y2: String(b.y),
          "data-from": edge.from,
          "data-to": edge.to,
          class: "edge" + fade + (hi ? " is-hot" : "") + style
        });
        line.appendChild(el("title", {})).textContent = (edge.relations || [edge.relation]).join(", ");
        root.appendChild(line);
        if (showLabels || hi) {
          var label = el("text", {
            x: String((a.x + b.x) / 2),
            y: String((a.y + b.y) / 2 - 6),
            class: "edge-label",
            "text-anchor": "middle"
          });
          label.textContent = (edge.relations || [edge.relation]).join(" · ");
          root.appendChild(label);
        }
      });
      nodes.forEach(function (node) {
        if (!visibleNode(node)) return;
        var fade = linked && !linked[node.id] ? " is-faded" : "";
        var g = el("g", {
          class: "g-node kind-" + node.kind + " type-" + (node.type || "") + (node.alias ? " is-alias" : "") + fade,
          "data-id": node.id,
          transform: "translate(0,0)"
        });
        var spec = shapePath(node.shape || (node.kind === "target" ? "circle-lg" : "circle"), node.x, node.y);
        var mark;
        if (spec.type === "rect") {
          mark = el("rect", { x: String(spec.x), y: String(spec.y), width: String(spec.w), height: String(spec.h) });
        } else if (spec.type === "poly") {
          mark = el("polygon", { points: spec.points.join(" ") });
        } else {
          mark = el("circle", { cx: String(spec.x), cy: String(spec.y), r: String(spec.r) });
          if (spec.dashed) mark.setAttribute("stroke-dasharray", "4 3");
        }
        mark.setAttribute("class", "node-shape");
        g.appendChild(mark);
        var textNode = el("text", {
          x: String(node.x),
          y: String(node.y + (node.kind === "target" ? 36 : 26)),
          "text-anchor": "middle",
          class: "node-label"
        });
        textNode.textContent = (node.label || "").slice(0, 22);
        g.appendChild(textNode);
        g.appendChild(el("title", {})).textContent = node.full_label || node.label || node.type;
        g.addEventListener("pointerdown", function (evt) {
          evt.stopPropagation();
          dragging = {
            id: node.id,
            x: node.x,
            y: node.y,
            px: evt.clientX,
            py: evt.clientY,
            moved: false,
            node: node
          };
          svg.classList.add("is-dragging");
        });
        g.addEventListener("pointerenter", function () {
          highlight(node.id);
        });
        g.addEventListener("pointerleave", function () {
          if (hovered === node.id) highlight(selected);
        });
        root.appendChild(g);
      });
    }

    function highlight(id) {
      hovered = id;
      var linked = id ? connectedIds(id) : null;
      svg.querySelectorAll(".g-node").forEach(function (g) {
        var nid = g.getAttribute("data-id");
        g.classList.toggle("is-faded", Boolean(linked) && !linked[nid]);
      });
      svg.querySelectorAll("line.edge").forEach(function (line) {
        var from = line.getAttribute("data-from");
        var to = line.getAttribute("data-to");
        var hot = Boolean(id) && (from === id || to === id);
        line.classList.toggle("is-hot", hot);
        line.classList.toggle("is-faded", Boolean(linked) && !linked[from]);
      });
    }

    function select(node) {
      selected = node ? node.id : null;
      if (node && window.SpectreDrawer) {
        window.SpectreDrawer.open(node.platform || node.label || node.type || "Node", nodeDrawer(node));
      }
      render();
    }

    svg.addEventListener("wheel", function (evt) {
      evt.preventDefault();
      var factor = evt.deltaY < 0 ? 1.08 : 0.92;
      var pt = screenToWorld(evt);
      view.k = Math.max(0.35, Math.min(3.4, view.k * factor));
      var rect = svg.getBoundingClientRect();
      var sx = ((evt.clientX - rect.left) / rect.width) * w;
      var sy = ((evt.clientY - rect.top) / rect.height) * h;
      view.x = sx - pt.x * view.k;
      view.y = sy - pt.y * view.k;
      render();
    }, { passive: false });

    svg.addEventListener("pointerdown", function (evt) {
      if (dragging) return;
      panning = { x: view.x, y: view.y, px: evt.clientX, py: evt.clientY };
    });
    window.addEventListener("pointermove", function (evt) {
      if (dragging) {
        var dist = Math.hypot(evt.clientX - dragging.px, evt.clientY - dragging.py);
        if (dist >= DRAG_THRESHOLD) dragging.moved = true;
        if (!dragging.moved) return;
        var node = nodes.find(function (n) { return n.id === dragging.id; });
        if (!node) return;
        var dx = (evt.clientX - dragging.px) / view.k;
        var dy = (evt.clientY - dragging.py) / view.k;
        node.x = dragging.x + dx * (w / svg.getBoundingClientRect().width);
        node.y = dragging.y + dy * (h / svg.getBoundingClientRect().height);
        render();
      } else if (panning) {
        var rect = svg.getBoundingClientRect();
        view.x = panning.x + (evt.clientX - panning.px) * (w / rect.width);
        view.y = panning.y + (evt.clientY - panning.py) * (h / rect.height);
        render();
      }
    });
    window.addEventListener("pointerup", function () {
      var drag = dragging;
      dragging = null;
      panning = null;
      svg.classList.remove("is-dragging");
      if (drag && !drag.moved && drag.node) {
        select(drag.node);
      }
    });

    function fit() {
      var vis = nodes.filter(visibleNode);
      if (!vis.length) {
        view.k = 1;
        view.x = 0;
        view.y = 0;
        render();
        return;
      }
      var minX = Math.min.apply(null, vis.map(function (n) { return n.x; }));
      var maxX = Math.max.apply(null, vis.map(function (n) { return n.x; }));
      var minY = Math.min.apply(null, vis.map(function (n) { return n.y; }));
      var maxY = Math.max.apply(null, vis.map(function (n) { return n.y; }));
      var pad = 72;
      var bw = Math.max(maxX - minX + pad * 2, 120);
      var bh = Math.max(maxY - minY + pad * 2, 120);
      view.k = Math.min(w / bw, h / bh, 2.4);
      view.x = w / 2 - ((minX + maxX) / 2) * view.k;
      view.y = h / 2 - ((minY + maxY) / 2) * view.k;
      render();
    }
    function center() {
      var target = nodes.find(function (n) { return n.kind === "target"; }) || nodes[0];
      view.k = 1.2;
      view.x = w / 2 - target.x * view.k;
      view.y = h / 2 - target.y * view.k;
      render();
    }
    function reset() {
      layoutConcentric();
      fit();
      selected = null;
      render();
    }
    function zoom(factor) {
      view.k = Math.max(0.35, Math.min(3.4, view.k * factor));
      view.x = w / 2 - (w / 2 - view.x) * factor;
      view.y = h / 2 - (h / 2 - view.y) * factor;
      render();
    }

    var fitBtn = document.getElementById("graph-fit");
    var centerBtn = document.getElementById("graph-center");
    var resetBtn = document.getElementById("graph-reset");
    var labelsBtn = document.getElementById("graph-labels");
    var zin = document.getElementById("graph-zoom-in");
    var zout = document.getElementById("graph-zoom-out");
    if (fitBtn) fitBtn.addEventListener("click", fit);
    if (centerBtn) centerBtn.addEventListener("click", center);
    if (resetBtn) resetBtn.addEventListener("click", reset);
    if (zin) zin.addEventListener("click", function () { zoom(1.12); });
    if (zout) zout.addEventListener("click", function () { zoom(0.9); });
    if (labelsBtn) labelsBtn.addEventListener("click", function () {
      showLabels = !showLabels;
      labelsBtn.setAttribute("aria-pressed", showLabels ? "true" : "false");
      render();
    });
    document.querySelectorAll("[data-graph-filter]").forEach(function (input) {
      var key = input.getAttribute("data-graph-filter");
      if (key && filters[key] === false) input.checked = false;
      if (key && filters[key] === true) input.checked = true;
      input.addEventListener("change", function () {
        filters[key] = input.checked;
        layoutConcentric();
        fit();
      });
    });
    fit();
  }

  document.addEventListener("DOMContentLoaded", initGraph);
})();
