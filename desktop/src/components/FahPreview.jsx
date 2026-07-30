import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import * as THREE from "three";

/**
 * Right-side FAH 3D preview using the **same on-disk visualization data** that
 * FAH Web Control renders:
 *   work/<unit>/viewerTop.json   — topology (elements)
 *   work/<unit>/viewerFrameN.json — atom coordinates
 *
 * Progress % is driven by the FAH unit's `wu_progress` (surfaced as
 * `progress_pct`). We do not invent coordinates; if no frames exist yet the
 * canvas stays empty with an honest message.
 *
 * Rendering uses THREE.Points (one BufferGeometry) so large proteins stay
 * responsive — per-atom Mesh spheres froze the webview on real FAH WUs.
 */

const ELEMENT_COLORS = {
  C: 0x909090,
  N: 0x3050f8,
  O: 0xff0d0d,
  S: 0xffff30,
  H: 0xffffff,
  P: 0xff8000,
  "?": 0x3ecf8e,
};

function colorForElement(el) {
  const key = String(el || "?").toUpperCase();
  return ELEMENT_COLORS[key] ?? ELEMENT_COLORS["?"];
}

function unitLabel(unit) {
  if (!unit) return null;
  const res = unit.resource || "GPU";
  const proj = unit.project || "?";
  const num =
    unit.number != null && unit.number !== ""
      ? `#${unit.number}`
      : unit.id
        ? String(unit.id).slice(0, 8) + "…"
        : "?";
  const pct =
    unit.progress_pct != null
      ? unit.progress_pct
      : Number(unit.progress) <= 1
        ? (Number(unit.progress) * 100).toFixed(1)
        : Number(unit.progress).toFixed(1);
  return { res, proj, num, pct, fullId: unit.id, state: unit.state || "" };
}

/** Normalize Tauri/serde payload (snake_case or camelCase). */
function normalizeViz(raw) {
  if (!raw || typeof raw !== "object") return null;
  const positions = raw.positions ?? raw.Positions;
  if (!Array.isArray(positions) || positions.length === 0) return null;
  return {
    work_dir: raw.work_dir ?? raw.workDir ?? "",
    unit_folder: raw.unit_folder ?? raw.unitFolder ?? "",
    frame_index: Number(raw.frame_index ?? raw.frameIndex ?? 0),
    frame_count: Number(raw.frame_count ?? raw.frameCount ?? 0),
    elements: raw.elements ?? [],
    atomic_numbers: raw.atomic_numbers ?? raw.atomicNumbers ?? [],
    positions,
  };
}

export default function FahPreview({ status, folding }) {
  const mountRef = useRef(null);
  const sceneRef = useRef(null);
  const [viz, setViz] = useState(null);
  const [vizError, setVizError] = useState("");
  const [vizLoading, setVizLoading] = useState(false);
  const [projectInfo, setProjectInfo] = useState(null);

  const units = status?.units ?? [];
  // Prefer a RUN/RUNNING unit; else first unit with an id.
  const primary =
    units.find((u) => /run/i.test(String(u.state || ""))) ?? units[0] ?? null;
  const label = unitLabel(primary);
  const projectId = primary?.project ? String(primary.project) : null;

  // Poll real FAH viz frames from the managed engine work directory.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        if (!cancelled) setVizLoading(true);
        const args = {};
        if (primary?.id) args.unitId = primary.id;
        const snap = await invoke("backend_fah_viz", args);
        if (cancelled) return;
        const norm = normalizeViz(snap);
        setViz(norm);
        setVizError("");
      } catch (err) {
        if (!cancelled) {
          setViz(null);
          setVizError(String(err?.message || err));
        }
      } finally {
        if (!cancelled) setVizLoading(false);
      }
    };
    tick();
    const id = setInterval(tick, 2500);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [folding, primary?.id]);

  // Official project blurb (plain text).
  useEffect(() => {
    if (!projectId || projectId === "0" || projectId === "unknown") {
      setProjectInfo(null);
      return;
    }
    let cancelled = false;
    fetch(`https://api.foldingathome.org/project/${encodeURIComponent(projectId)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (!cancelled) setProjectInfo(data);
      })
      .catch(() => {
        if (!cancelled) setProjectInfo(null);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  // Three.js scene shell (once).
  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const width = Math.max(mount.clientWidth || 320, 64);
    const height = Math.max(mount.clientHeight || 280, 64);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.01, 2000);
    camera.position.set(0, 0, 40);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setClearColor(0x0a0c14, 1);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height, false);
    mount.appendChild(renderer.domElement);

    scene.add(new THREE.AmbientLight(0xffffff, 0.85));
    const key = new THREE.DirectionalLight(0xffffff, 0.55);
    key.position.set(20, 30, 40);
    scene.add(key);

    const atomGroup = new THREE.Group();
    scene.add(atomGroup);
    sceneRef.current = { scene, camera, renderer, atomGroup, points: null };

    let raf = 0;
    const animate = () => {
      raf = requestAnimationFrame(animate);
      atomGroup.rotation.y += 0.004;
      renderer.render(scene, camera);
    };
    animate();

    const onResize = () => {
      const w = Math.max(mount.clientWidth || 320, 64);
      const h = Math.max(mount.clientHeight || 280, 64);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h, false);
    };
    window.addEventListener("resize", onResize);
    // Layout may settle after first paint (sticky column).
    const ro =
      typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(onResize)
        : null;
    ro?.observe(mount);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      ro?.disconnect();
      const pts = sceneRef.current?.points;
      if (pts) {
        pts.geometry?.dispose?.();
        pts.material?.dispose?.();
      }
      while (atomGroup.children.length) {
        const c = atomGroup.children.pop();
        c.geometry?.dispose?.();
        c.material?.dispose?.();
      }
      renderer.dispose();
      if (renderer.domElement.parentNode === mount) {
        mount.removeChild(renderer.domElement);
      }
      sceneRef.current = null;
    };
  }, []);

  // Update point cloud when viz snapshot changes.
  useEffect(() => {
    const ctx = sceneRef.current;
    if (!ctx) return;
    const { atomGroup, camera, renderer, scene } = ctx;

    // Clear previous points.
    while (atomGroup.children.length) {
      const c = atomGroup.children.pop();
      c.geometry?.dispose?.();
      c.material?.dispose?.();
    }
    ctx.points = null;

    if (!viz?.positions?.length) {
      renderer.render(scene, camera);
      return;
    }

    const positions = viz.positions;
    const elements = viz.elements || [];
    const n = positions.length;

    let cx = 0;
    let cy = 0;
    let cz = 0;
    for (let i = 0; i < n; i++) {
      const p = positions[i];
      cx += Number(p[0]) || 0;
      cy += Number(p[1]) || 0;
      cz += Number(p[2]) || 0;
    }
    cx /= n;
    cy /= n;
    cz /= n;

    const posArr = new Float32Array(n * 3);
    const colArr = new Float32Array(n * 3);
    const color = new THREE.Color();
    let maxR = 1;
    for (let i = 0; i < n; i++) {
      const p = positions[i];
      const x = (Number(p[0]) || 0) - cx;
      const y = (Number(p[1]) || 0) - cy;
      const z = (Number(p[2]) || 0) - cz;
      posArr[i * 3] = x;
      posArr[i * 3 + 1] = y;
      posArr[i * 3 + 2] = z;
      maxR = Math.max(maxR, Math.sqrt(x * x + y * y + z * z));
      color.setHex(colorForElement(elements[i]));
      colArr[i * 3] = color.r;
      colArr[i * 3 + 1] = color.g;
      colArr[i * 3 + 2] = color.b;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(posArr, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(colArr, 3));

    const mat = new THREE.PointsMaterial({
      size: Math.max(0.35, maxR * 0.018),
      vertexColors: true,
      sizeAttenuation: true,
    });
    const points = new THREE.Points(geo, mat);
    atomGroup.add(points);
    ctx.points = points;

    camera.position.set(0, maxR * 0.12, maxR * 2.6);
    camera.near = Math.max(0.01, maxR * 0.005);
    camera.far = Math.max(100, maxR * 25);
    camera.updateProjectionMatrix();
    camera.lookAt(0, 0, 0);
    renderer.render(scene, camera);
  }, [viz]);

  const atomCount = viz?.positions?.length ?? 0;

  return (
    <aside className="fah-preview glass" aria-label="Folding@home 3D work preview">
      <div className="fah-preview__header">
        <h3>3D work preview</h3>
      </div>

      <div className="fah-preview__canvas" ref={mountRef} />

      <div className="fah-preview__meta">
        {label ? (
          <>
            <p className="status-ok fah-preview__progress-line">
              {label.res} Progress {label.pct}%
            </p>
            <p className="muted">
              Project {label.proj} · WU {label.num}
              {label.state ? ` · ${label.state}` : ""}
            </p>
            {label.fullId && (
              <p className="fah-preview__id" title={label.fullId}>
                id {label.fullId}
              </p>
            )}
          </>
        ) : (
          <p className="placeholder-note">
            {folding
              ? "Waiting for a Folding@home work unit…"
              : "Start contributing to load a work unit."}
          </p>
        )}

        {viz && atomCount > 0 ? (
          <p className="muted">
            Frame {viz.frame_index + 1}/{viz.frame_count} · {atomCount} atoms
            {viz.unit_folder ? ` (work/${viz.unit_folder.slice(0, 12)}…)` : ""}
          </p>
        ) : (
          <p className="placeholder-note">
            {vizError
              ? `Viz unavailable: ${vizError}`
              : vizLoading
                ? "Loading FAH viewer frames…"
                : folding || label
                  ? "No viewer frames on disk yet — FAH writes them after the core starts (often a few minutes into RUN)."
                  : "No viewer frames — start contributing first."}
          </p>
        )}

        {projectInfo?.cause && (
          <p className="fah-preview__cause">{projectInfo.cause}</p>
        )}
        {projectInfo?.institution && (
          <p className="muted">{projectInfo.institution}</p>
        )}
      </div>
    </aside>
  );
}
