import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import * as THREE from "three";

/**
 * Right-side FAH 3D preview using the **same on-disk visualization data** that
 * FAH Web Control (fah-web-client-bastet) renders:
 *   work/<unit>/viewerTop.json   — topology (elements)
 *   work/<unit>/viewerFrameN.json — atom coordinates
 *
 * Progress % is driven by the FAH unit's `wu_progress` (surfaced as
 * `progress_pct`, e.g. "25.5") — aligned with Web Control's Progress column.
 *
 * We do not invent coordinates; if no frames exist yet the canvas is empty
 * with an honest message + link to official Web Control.
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
      : (Number(unit.progress) <= 1
          ? (Number(unit.progress) * 100).toFixed(1)
          : Number(unit.progress).toFixed(1));
  return { res, proj, num, pct, fullId: unit.id, state: unit.state || "" };
}

export default function FahPreview({ status, folding }) {
  const mountRef = useRef(null);
  const sceneRef = useRef(null);
  const [viz, setViz] = useState(null);
  const [vizError, setVizError] = useState("");
  const [projectInfo, setProjectInfo] = useState(null);

  const units = status?.units ?? [];
  // Prefer a RUN/RUNNING unit; else first unit.
  const primary =
    units.find((u) => /run/i.test(String(u.state || ""))) ?? units[0] ?? null;
  const label = unitLabel(primary);
  const projectId = primary?.project ? String(primary.project) : null;

  // Poll real FAH viz frames from the managed engine work directory.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const snap = await invoke("backend_fah_viz");
        if (!cancelled) {
          setViz(snap ?? null);
          setVizError("");
        }
      } catch (err) {
        if (!cancelled) {
          setViz(null);
          setVizError(String(err?.message || err));
        }
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

  // Three.js scene: render real FAH atom coordinates when available.
  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const width = mount.clientWidth || 320;
    const height = mount.clientHeight || 320;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0b1220);
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.01, 500);
    camera.position.set(0, 0, 40);

    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height);
    mount.appendChild(renderer.domElement);

    scene.add(new THREE.AmbientLight(0xffffff, 0.65));
    const key = new THREE.DirectionalLight(0xffffff, 0.9);
    key.position.set(20, 30, 40);
    scene.add(key);

    const atomGroup = new THREE.Group();
    scene.add(atomGroup);
    sceneRef.current = { scene, camera, renderer, atomGroup };

    let raf = 0;
    const animate = () => {
      raf = requestAnimationFrame(animate);
      atomGroup.rotation.y += 0.004;
      renderer.render(scene, camera);
    };
    animate();

    const onResize = () => {
      const w = mount.clientWidth || 320;
      const h = mount.clientHeight || 320;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
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

  // Update atom mesh when viz snapshot changes.
  useEffect(() => {
    const ctx = sceneRef.current;
    if (!ctx || !viz?.positions?.length) return;
    const { atomGroup, camera } = ctx;

    while (atomGroup.children.length) {
      const c = atomGroup.children.pop();
      c.geometry?.dispose?.();
      c.material?.dispose?.();
    }

    const positions = viz.positions;
    const elements = viz.elements || [];
    // Subsample very large proteins for GPU sanity (still real FAH coords).
    const stride = positions.length > 8000 ? Math.ceil(positions.length / 8000) : 1;

    let cx = 0,
      cy = 0,
      cz = 0,
      n = 0;
    for (let i = 0; i < positions.length; i += stride) {
      cx += positions[i][0];
      cy += positions[i][1];
      cz += positions[i][2];
      n += 1;
    }
    cx /= n || 1;
    cy /= n || 1;
    cz /= n || 1;

    const geo = new THREE.SphereGeometry(0.18, 8, 8);
    for (let i = 0; i < positions.length; i += stride) {
      const el = elements[i] || "?";
      const mat = new THREE.MeshStandardMaterial({
        color: colorForElement(el),
        metalness: 0.15,
        roughness: 0.55,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(
        positions[i][0] - cx,
        positions[i][1] - cy,
        positions[i][2] - cz
      );
      atomGroup.add(mesh);
    }

    // Fit camera to structure radius.
    let maxR = 1;
    for (let i = 0; i < positions.length; i += stride) {
      const dx = positions[i][0] - cx;
      const dy = positions[i][1] - cy;
      const dz = positions[i][2] - cz;
      maxR = Math.max(maxR, Math.sqrt(dx * dx + dy * dy + dz * dz));
    }
    camera.position.set(0, maxR * 0.15, maxR * 2.4);
    camera.near = maxR * 0.01;
    camera.far = maxR * 20;
    camera.updateProjectionMatrix();
    camera.lookAt(0, 0, 0);
  }, [viz]);

  return (
    <aside className="fah-preview" aria-label="Folding@home 3D work preview">
      <div className="fah-preview__header">
        <h3>3D work preview</h3>
        <p className="muted">
          Real FAH frames (viewerTop / viewerFrame) — same data as{" "}
          <a
            href="https://github.com/foldingathome/fah-web-client-bastet"
            target="_blank"
            rel="noreferrer"
          >
            fah-web-client-bastet
          </a>
        </p>
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

        {viz ? (
          <p className="muted">
            Frame {viz.frame_index + 1}/{viz.frame_count} · {viz.positions?.length ?? 0} atoms
            (FAH work/{viz.unit_folder})
          </p>
        ) : (
          <p className="placeholder-note">
            {vizError
              ? `Viz unavailable: ${vizError}`
              : "No viewer frames on disk yet — FAH writes them while the unit runs."}
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
