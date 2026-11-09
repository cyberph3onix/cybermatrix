"use client";

import Link from "next/link";
import { useEffect, useRef } from "react";

// Ported from the Claude Design project "CyberMatrix Landing.dc.html".
const INK = "#d6f28c";
const ACC = "#a9c95e";
const HI = "#eaffb0";
const LV = 7;

function startEye(c: HTMLCanvasElement, panel: () => HTMLElement | null): () => void {
  const ctx = c.getContext("2d");
  if (!ctx) return () => {};
  const inks: string[] = [];
  const r = parseInt(INK.slice(1, 3), 16), g = parseInt(INK.slice(3, 5), 16), b = parseInt(INK.slice(5, 7), 16);
  for (let i = 1; i <= LV; i++) inks.push(`rgba(${r},${g},${b},${(0.08 + (0.92 * i) / LV).toFixed(3)})`);

  let W = 0, H = 0, dpr = 1;
  const resize = () => {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = c.clientWidth;
    H = c.clientHeight;
    c.width = W * dpr;
    c.height = H * dpr;
  };
  resize();
  window.addEventListener("resize", resize);

  const t0 = performance.now();
  let mouse: { x: number; y: number; at: number } | null = null;
  let lastEye: { ex: number; ey: number; R: number } | null = null;
  const onMove = (e: PointerEvent) => {
    const rc = c.getBoundingClientRect();
    mouse = { x: e.clientX - rc.left, y: e.clientY - rc.top, at: performance.now() - t0 };
  };
  window.addEventListener("pointermove", onMove);

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const gaze = { x: 0, y: 0 };
  let target = { x: 0, y: 0 }, nextSac = 0, blink = 1, nextBlink = 2500, raf = 0;
  const smooth = (a: number, b: number, x: number) => {
    const t = Math.max(0, Math.min(1, (x - a) / (b - a)));
    return t * t * (3 - 2 * t);
  };

  const frame = (now: number) => {
    const t = now - t0;
    if (mouse && lastEye && t - mouse.at < 3000) {
      let dx = (mouse.x - lastEye.ex) / (lastEye.R * 2.2), dy = (mouse.y - lastEye.ey) / (lastEye.R * 2.2);
      const m = Math.hypot(dx, dy);
      if (m > 1) { dx /= m; dy /= m; }
      target = { x: dx * 0.55, y: dy * 0.34 };
      nextSac = t + 400;
    } else if (t > nextSac && !reduced) {
      const a = Math.random() * Math.PI * 2, m = Math.random() ** 0.6;
      target = { x: Math.cos(a) * m * 0.55, y: Math.sin(a) * m * 0.32 };
      nextSac = t + 500 + Math.random() * 1600;
    }
    gaze.x += (target.x - gaze.x) * 0.16;
    gaze.y += (target.y - gaze.y) * 0.16;
    const bt = t - nextBlink;
    if (reduced || bt < 0) blink = 1;
    else if (bt < 260) blink = Math.abs(Math.cos((bt / 260) * Math.PI)) * 0.95 + 0.05;
    else { nextBlink = t + 3000 + Math.random() * 4000; blink = 1; }

    const pEl = panel(), cr = c.getBoundingClientRect(), prc = pEl ? pEl.getBoundingClientRect() : null;
    const pr = prc ? prc.right - cr.left : W * 0.4, pt = prc ? prc.top - cr.top : H * 0.55;
    let R: number, ex: number, ey: number;
    if (W < 760) {
      const band = Math.max(120, pt - 70);
      R = Math.min(W * 0.42, band / 1.15); ex = W * 0.5; ey = 70 + band / 2;
    } else {
      R = Math.min((W - pr - 20) / 2.3, H * 0.42); ex = pr + R * 1.15; ey = H * 0.5;
    }
    lastEye = { ex, ey, R };
    const irisR = R * 0.4, ix = ex + gaze.x * R * 0.7, iy = ey + gaze.y * R * 0.5;
    const pupilR = irisR * (0.42 + 0.05 * Math.sin(t / 900));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    // Pixel-halftone eye, bucketed into LV brightness levels so each level is a single fill.
    const S = Math.max(5, Math.round(R / 34)), paths = Array.from({ length: LV }, () => new Path2D());
    const x0 = Math.max(0, ex - R * 1.9), x1 = Math.min(W, ex + R * 1.9), y0 = Math.max(0, ey - R * 1.3), y1 = Math.min(H, ey + R * 1.3);
    for (let y = y0 - (y0 % S); y < y1; y += S)
      for (let x = x0 - (x0 % S); x < x1; x += S) {
        const nx = (x - ex) / R, ny = (y - ey) / R;
        const env = 1 - smooth(1.2, 1.85, Math.hypot(nx * 0.95, ny * 1.35));
        if (env <= 0) continue;
        let br: number;
        const k = Math.max(0, 1 - nx * nx), up = 0.58 * Math.pow(k, 0.85) * blink, lo = 0.44 * Math.pow(k, 0.95) * blink;
        if (Math.abs(nx) < 1 && ny > -up && ny < lo) {
          const d = Math.hypot(x - ix, y - iy);
          const edge = Math.min(ny + up, lo - ny) / 0.12;
          if (d < pupilR) br = 0.02;
          else if (d < irisR) {
            const a = Math.atan2(y - iy, x - ix);
            br = 0.32 + 0.14 * Math.sin(a * 23 + d * 0.05) + 0.25 * ((d - pupilR) / (irisR - pupilR));
            if (d > irisR * 0.9) br *= 0.45;
          } else br = 0.82 - 0.35 * Math.abs(nx) ** 2;
          br *= Math.min(1, 0.35 + edge * 0.65);
          if (Math.hypot(x - (ix - irisR * 0.32), y - (iy - irisR * 0.34)) < irisR * 0.2) br = 1;
        } else {
          const crease = Math.abs(ny + up + 0.2 + 0.05 * nx * nx);
          br = 0.12 + 0.28 * Math.max(0, 1 - crease / 0.06) +
            0.1 * Math.max(0, 1 - Math.abs(ny - lo - 0.12) / 0.05) * (Math.abs(nx) < 1 ? 1 : 0);
          br += 0.06 * Math.sin(nx * 40 + ny * 13) * Math.sin(ny * 31);
        }
        br *= env;
        const lv = Math.min(LV - 1, Math.floor(br * LV));
        if (lv < 0 || br < 0.05) continue;
        const s = S * (0.35 + 0.6 * br);
        paths[lv].rect(x - s / 2, y - s / 2, s, s);
      }
    for (let i = 0; i < LV; i++) { ctx.fillStyle = inks[i]; ctx.fill(paths[i]); }

    // Tracking grid around the iris.
    const cell = irisR * 0.42, gx0 = ex - Math.round(R / cell) * cell, gy0 = ey - Math.round(R / cell) * cell;
    ctx.lineWidth = 1; ctx.strokeStyle = ACC;
    for (let gy = gy0; gy < ey + R; gy += cell)
      for (let gx = gx0; gx < ex + R * 1.1; gx += cell) {
        const d = Math.hypot(gx + cell / 2 - ix, gy + cell / 2 - iy);
        if (d < irisR * 1.25 && blink > 0.4) {
          ctx.globalAlpha = 0.55 + 0.45 * Math.max(0, 1 - d / (irisR * 1.25));
          ctx.strokeRect(gx + 0.5, gy + 0.5, cell - 1, cell - 1);
          if ((Math.floor(t / 140) * 7 + Math.round(gx * 3 + gy)) % 11 === 0) {
            ctx.globalAlpha = 0.18; ctx.fillStyle = ACC; ctx.fillRect(gx, gy, cell, cell);
          }
        }
      }
    ctx.globalAlpha = 1;

    // Lock box + crosshair.
    ctx.strokeStyle = HI;
    const L = irisR * 1.45, bx = ix - L / 2, by = iy - L / 2, tk = L * 0.18;
    ctx.beginPath();
    for (const [px, py, sx, sy] of [[bx, by, 1, 1], [bx + L, by, -1, 1], [bx, by + L, 1, -1], [bx + L, by + L, -1, -1]]) {
      ctx.moveTo(px + sx * tk, py); ctx.lineTo(px, py); ctx.lineTo(px, py + sy * tk);
    }
    ctx.moveTo(ix - 8, iy); ctx.lineTo(ix + 8, iy); ctx.moveTo(ix, iy - 8); ctx.lineTo(ix, iy + 8);
    ctx.stroke();
    ctx.font = "11px ui-monospace,SFMono-Regular,Menlo,monospace"; ctx.fillStyle = HI;
    ctx.fillText(`X ${(gaze.x * 100).toFixed(1).padStart(6)}  Y ${(gaze.y * 100).toFixed(1).padStart(6)}`, bx, by - 8);

    // Status readout.
    const sx = ex - R * 0.95, sy = ey + R * 0.72;
    ctx.font = "13px ui-monospace,SFMono-Regular,Menlo,monospace"; ctx.fillStyle = INK;
    const st = Math.hypot(target.x - gaze.x, target.y - gaze.y) > 0.04 ? "Saccade" : "Fixation";
    ctx.fillText(`ID> ${(0x5583035 + Math.floor(t / 4000)).toString(16).toUpperCase()}-13`, sx, sy);
    ctx.fillText(`Gaze> ${st}`, sx, sy + 19);
    ctx.fillStyle = HI;
    ctx.fillText(`Status> ${blink < 0.5 ? "Reacquiring" : "Tracking"}${Math.floor(t / 400) % 2 ? "_" : ""}`, sx, sy + 38);

    raf = requestAnimationFrame(frame);
  };
  raf = requestAnimationFrame(frame);

  return () => {
    cancelAnimationFrame(raf);
    window.removeEventListener("resize", resize);
    window.removeEventListener("pointermove", onMove);
  };
}

export default function Landing() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const c = canvasRef.current;
    if (!c) return;
    return startEye(c, () => panelRef.current);
  }, []);

  return (
    <main
      className="landing"
      style={{
        position: "relative",
        minHeight: "100dvh",
        overflow: "hidden",
        background: "radial-gradient(ellipse at 65% 50%, #1c2412 0%, #11160b 70%)",
        color: INK,
        fontFamily: "var(--font-share-tech-mono), ui-monospace, monospace",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <canvas
        ref={canvasRef}
        aria-hidden="true"
        style={{ position: "absolute", inset: 0, width: "100%", height: "100%", display: "block" }}
      />
      <div aria-hidden="true" style={{ position: "absolute", inset: 0, pointerEvents: "none", background: "linear-gradient(90deg, #11160b 0%, rgba(17,22,11,0.75) 30%, rgba(17,22,11,0) 58%)" }} />
      <div aria-hidden="true" style={{ position: "absolute", inset: 0, pointerEvents: "none", zIndex: 3, background: "repeating-linear-gradient(0deg, rgba(0,0,0,0.18) 0px, rgba(0,0,0,0.18) 1px, transparent 1px, transparent 3px)" }} />
      <div aria-hidden="true" style={{ position: "absolute", inset: 0, pointerEvents: "none", zIndex: 3, boxShadow: "inset 0 0 180px rgba(0,0,0,0.75)" }} />

      <header style={{ position: "relative", zIndex: 2, display: "flex", alignItems: "center", gap: 18, padding: "24px clamp(20px,5vw,64px)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 15, letterSpacing: "0.12em", textTransform: "uppercase", textShadow: "0 0 8px rgba(214,242,140,0.45)" }}>
          <span style={{ width: 10, height: 10, background: INK, display: "block", boxShadow: "0 0 8px rgba(214,242,140,0.6)" }} />
          <span>CyberMatrix</span>
        </div>
        <div style={{ flex: 1, borderTop: "1px dashed rgba(201,231,122,0.45)" }} />
      </header>

      {/* On narrow screens the top padding jumps to 56vh, leaving room for the eye above the copy. */}
      <section style={{ position: "relative", zIndex: 2, flex: 1, display: "flex", alignItems: "center", padding: "clamp(24px, (760px - 100vw) * 1000, 56vh) clamp(20px,5vw,64px) 64px" }}>
        <div ref={panelRef} style={{ position: "relative", maxWidth: "clamp(min(500px, 46vw), (760px - 100vw) * 1000, 100%)", width: "100%", display: "flex", flexDirection: "column", gap: 22 }}>
          <h1 style={{ margin: 0, fontFamily: "var(--font-vt323), var(--font-share-tech-mono), monospace", fontWeight: 400, fontSize: "clamp(56px,8vw,120px)", lineHeight: 0.85, letterSpacing: "0.02em", textTransform: "uppercase", color: "#e2fa9c", textShadow: "0 0 18px rgba(214,242,140,0.55), 0 0 2px rgba(214,242,140,0.9)" }}>
            CyberMatrix
          </h1>
          <p style={{ margin: 0, fontSize: 17, lineHeight: 1.6, textTransform: "uppercase", letterSpacing: "0.03em", color: "#c9e77a", textWrap: "pretty", textShadow: "0 0 6px rgba(201,231,122,0.35)" }}>
            &gt; Submit a URL, domain, email, message or QR image and get an evidence-based risk assessment. Every
            report can be committed on-chain and verified by anyone.
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 20, paddingTop: 4 }}>
            <Link href="/investigate" className="landing-cta">
              <span>Open CyberMatrix</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M5 12h14" />
                <path d="m12 5 7 7-7 7" />
              </svg>
            </Link>
            <a href="https://github.com/cyberph3onix/cybermatrix" className="landing-link">
              /source ↗
            </a>
          </div>
        </div>
      </section>
    </main>
  );
}
