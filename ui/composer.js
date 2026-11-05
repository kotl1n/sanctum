(function install() {
  "use strict";
  if (location.protocol !== "app:" || location.hostname !== "-") return;
  if (window.__sanctumComposer || !globalThis.Highlight || !CSS.highlights) return;
  if (!document.documentElement) { document.addEventListener("DOMContentLoaded", install, { once: true }); return; }
  const selector = '.ProseMirror[contenteditable="true"], [role="textbox"][contenteditable="true"]';
  const name = "sanctum-private";
  const states = new Map();
  let nextId = 1;
  let active = true;
  const style = new CSSStyleSheet();
  style.replaceSync(`${selector.split(",").map(item => `${item}::highlight(${name})`).join(",")} { color: color-mix(in srgb, var(--sanctum-private-ink, CanvasText) 25%, transparent); }`);
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, style];
  const block = new Set(["P", "DIV", "LI", "PRE", "BLOCKQUOTE", "H1", "H2", "H3"]);
  function flatten(root) {
    let text = "";
    const segments = [];
    function visit(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        const start = text.length;
        text += node.data;
        segments.push({ node, start, end: text.length });
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        if (node !== root && node.getAttribute("contenteditable") === "false") return;
        if (node.tagName === "BR") { text += "\n"; return; }
        const isBlock = node !== root && block.has(node.tagName);
        if (isBlock && text && !text.endsWith("\n")) text += "\n";
        for (const child of node.childNodes) visit(child);
        if (isBlock && text && !text.endsWith("\n")) text += "\n";
      }
    }
    visit(root);
    return { text, segments };
  }
  function paint() {
    const ranges = [];
    for (const state of states.values()) if (state.root.isConnected && active) {
      const color = getComputedStyle(state.root).color;
      if (state.ink !== color) { state.ink = color; state.root.style.setProperty("--sanctum-private-ink", color); }
      ranges.push(...state.ranges);
    }
    CSS.highlights.set(name, new Highlight(...ranges));
  }
  function rangesFor(current, spans) {
    const ranges = [];
    for (const [start, end] of spans) {
      const first = current.segments.find(item => item.start <= start && item.end > start);
      const last = current.segments.find(item => item.start < end && item.end >= end);
      if (!first || !last) continue;
      const range = document.createRange();
      range.setStart(first.node, start - first.start);
      range.setEnd(last.node, end - last.start);
      ranges.push(range);
    }
    return ranges;
  }
  function moveSpans(previous, text, spans) {
    if (previous === text) return spans;
    let start = 0, oldEnd = previous.length, newEnd = text.length;
    while (start < oldEnd && start < newEnd && previous[start] === text[start]) start++;
    while (oldEnd > start && newEnd > start && previous[oldEnd - 1] === text[newEnd - 1]) { oldEnd--; newEnd--; }
    const delta = newEnd - oldEnd;
    return spans.flatMap(([from, to]) => {
      if (to <= start) {
        if (to === start && oldEnd === start) to += /^\S*/u.exec(text.slice(start, newEnd))[0].length;
      } else if (from >= oldEnd) { from += delta; to += delta; }
      else {
        if (from >= start && to <= oldEnd && (from > start || to < oldEnd)) return [];
        from = Math.min(from, start);
        to = to > oldEnd ? to + delta : newEnd;
      }
      return to > from ? [[from, to]] : [];
    });
  }
  function schedule(state) {
    state.revision++;
    const current = flatten(state.root);
    state.spans = active ? moveSpans(state.visualText, current.text, state.spans) : [];
    state.visualText = current.text;
    state.ranges = rangesFor(current, state.spans);
    paint();
    clearTimeout(state.timer);
    if (!active || state.composing) return;
    state.timer = setTimeout(() => {
      if (!state.root.isConnected) return;
      const { text } = flatten(state.root);
      if (!text) return;
      state.text = text;
      if (typeof window.__sanctumLocalInspect === "function") {
        window.__sanctumLocalInspect(JSON.stringify({ editor: state.id, revision: state.revision, text }));
      }
    }, 140);
  }
  function scan() {
    for (const [id, state] of states) if (!state.root.isConnected) {
      clearTimeout(state.timer); states.delete(id);
    }
    for (const root of document.querySelectorAll(selector)) {
      if ([...states.values()].some(state => state.root === root)) continue;
      const state = { root, id: nextId++, revision: 0, ranges: [], spans: [], visualText: "", composing: false, text: "" };
      states.set(state.id, state);
      root.addEventListener("input", () => schedule(state));
      root.addEventListener("compositionstart", () => { state.composing = true; schedule(state); });
      root.addEventListener("compositionend", () => { state.composing = false; schedule(state); });
      schedule(state);
    }
    paint();
  }
  function apply(message) {
    const state = states.get(message.editor);
    if (!state || state.revision !== message.revision || state.composing || !state.root.isConnected) return;
    const current = flatten(state.root);
    if (current.text !== state.text) return;
    const spans = [];
    if (message.active && active) for (const span of message.spans || []) {
      if (!Array.isArray(span) || span.length !== 2) continue;
      const [start, end] = span;
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > current.text.length) continue;
      spans.push([start, end]);
    }
    state.spans = spans;
    state.visualText = current.text;
    state.ranges = rangesFor(current, spans);
    paint();
  }
  function enabled(value) {
    active = Boolean(value);
    for (const state of states.values()) schedule(state);
    paint();
  }
  const observer = new MutationObserver(records => {
    let discover = false;
    const dirty = new Set();
    for (const record of records) {
      for (const state of states.values()) if (record.type !== "attributes" && state.root.contains(record.target)) dirty.add(state);
      if (record.type === "attributes" && record.target.matches(selector)) discover = true;
      if (record.type === "childList") {
        for (const node of record.addedNodes) if (node.nodeType === Node.ELEMENT_NODE && (node.matches(selector) || node.querySelector(selector))) discover = true;
        if ([...states.values()].some(state => !state.root.isConnected)) discover = true;
      }
    }
    if (discover) scan();
    for (const state of dirty) schedule(state);
    if (records.some(record => record.type === "attributes")) paint();
  });
  observer.observe(document.documentElement, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["class", "style", "data-theme", "contenteditable"] });
  window.__sanctumComposer = Object.freeze({ apply, enabled,
    refresh() { scan(); for (const state of states.values()) schedule(state); },
    status() { return { installed: true, active, editors: states.size, ranges: [...states.values()].reduce((n,state) => n + state.ranges.length, 0), opacity: 0.25 }; }
  });
  scan();
})();
