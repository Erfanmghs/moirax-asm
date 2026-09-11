/* ASM motion layer -- canvas field + panel/card choreography.
   Honors prefers-reduced-motion. No network, no inline handlers. */
"use strict";

(function () {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  const pointer = { x: 0.5, y: 0.22, live: false };
  let raf = 0;

  function reduced() {
    return reduce.matches;
  }

  function enterPanel(panel) {
    if (!panel) return;
    panel.classList.remove("fx-in");
    void panel.offsetWidth;
    panel.classList.add("fx-in");
  }

  function bump(el) {
    if (!el) return;
    el.classList.remove("fx-bump");
    void el.offsetWidth;
    el.classList.add("fx-bump");
  }

  function staggerBoard(root) {
    if (!root) return;
    const cards = root.querySelectorAll(".scan-card");
    cards.forEach((card, i) => {
      card.style.setProperty("--i", String(i));
      card.classList.add("fx-pop");
    });
  }

  function bindHero() {
    const hero = document.getElementById("hero-banner");
    if (!hero) return;
    hero.addEventListener("pointermove", (ev) => {
      const box = hero.getBoundingClientRect();
      const x = ((ev.clientX - box.left) / Math.max(1, box.width)) * 100;
      const y = ((ev.clientY - box.top) / Math.max(1, box.height)) * 100;
      hero.style.setProperty("--mx", x.toFixed(2) + "%");
      hero.style.setProperty("--my", y.toFixed(2) + "%");
    });
  }

  function bindRipple() {
    document.addEventListener("click", (ev) => {
      const btn = ev.target.closest("button");
      if (!btn || btn.disabled || reduced()) return;
      const box = btn.getBoundingClientRect();
      const mark = document.createElement("span");
      mark.className = "fx-ripple";
      mark.style.left = (ev.clientX - box.left) + "px";
      mark.style.top = (ev.clientY - box.top) + "px";
      btn.classList.add("fx-rippling");
      btn.appendChild(mark);
      setTimeout(() => {
        mark.remove();
        if (!btn.querySelector(".fx-ripple")) btn.classList.remove("fx-rippling");
      }, 520);
    }, true);
  }

  function bindBoard() {
    const board = document.getElementById("scan-board");
    if (!board || typeof MutationObserver === "undefined") return;
    staggerBoard(board);
    const obs = new MutationObserver(() => staggerBoard(board));
    obs.observe(board, { childList: true });
  }

  function field() {
    const canvas = document.getElementById("fx-field");
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext("2d");
    let nodes = [];
    let w = 0;
    let h = 0;

    function seed() {
      const area = w * h;
      const n = Math.max(18, Math.min(52, Math.floor(area / 28000)));
      nodes = [];
      for (let i = 0; i < n; i += 1) {
        nodes.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.28,
          vy: (Math.random() - 0.5) * 0.28,
          r: 0.8 + Math.random() * 1.4,
        });
      }
    }

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = w + "px";
      canvas.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      seed();
    }

    function tick() {
      raf = 0;
      if (reduced() || document.hidden) return;
      const mx = pointer.x * w;
      const my = pointer.y * h;
      ctx.clearRect(0, 0, w, h);
      for (let i = 0; i < nodes.length; i += 1) {
        const a = nodes[i];
        if (pointer.live) {
          const dx = mx - a.x;
          const dy = my - a.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < 220 * 220 && d2 > 16) {
            a.vx += dx * 0.000012;
            a.vy += dy * 0.000012;
          }
        }
        a.x += a.vx;
        a.y += a.vy;
        if (a.x < -8) a.x = w + 8;
        if (a.x > w + 8) a.x = -8;
        if (a.y < -8) a.y = h + 8;
        if (a.y > h + 8) a.y = -8;
        a.vx *= 0.995;
        a.vy *= 0.995;
      }
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i += 1) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j += 1) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist > 130) continue;
          const alpha = (1 - dist / 130) * 0.16;
          ctx.strokeStyle = "rgba(34, 211, 238, " + alpha.toFixed(3) + ")";
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
      for (let i = 0; i < nodes.length; i += 1) {
        const a = nodes[i];
        ctx.fillStyle = "rgba(103, 232, 249, 0.55)";
        ctx.beginPath();
        ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
        ctx.fill();
      }
      raf = window.requestAnimationFrame(tick);
    }

    function start() {
      if (reduced()) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        canvas.classList.add("fx-off");
        return;
      }
      canvas.classList.remove("fx-off");
      if (!raf) raf = window.requestAnimationFrame(tick);
    }

    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        if (raf) window.cancelAnimationFrame(raf);
        raf = 0;
      } else start();
    });
    const onReduce = () => {
      if (raf) window.cancelAnimationFrame(raf);
      raf = 0;
      resize();
      start();
    };
    if (reduce.addEventListener) reduce.addEventListener("change", onReduce);
    else if (reduce.addListener) reduce.addListener(onReduce);
    window.addEventListener("pointermove", (ev) => {
      pointer.x = ev.clientX / Math.max(1, window.innerWidth);
      pointer.y = ev.clientY / Math.max(1, window.innerHeight);
      pointer.live = true;
    }, { passive: true });
    resize();
    start();
  }

  window.asmMotion = { enterPanel: enterPanel, bump: bump, staggerBoard: staggerBoard };
  bindHero();
  bindRipple();
  bindBoard();
  field();
})();
