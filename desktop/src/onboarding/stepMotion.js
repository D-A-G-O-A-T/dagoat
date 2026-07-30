// Shared step-transition choreography (T28 R1). Extracted verbatim from
// OnboardingWizard.jsx so overlays that switch internal views (AddWalletOverlay)
// inherit the wizard's approved presentation instead of hand-rolling their own.
export const stepVariants = {
  enter: { x: 64, opacity: 0 },
  center: { x: 0, opacity: 1, transition: { duration: 0.42, ease: [0.3, 1.25, 0.5, 1] } },
  exit: { x: -44, opacity: 0, transition: { duration: 0.24, ease: [0.4, 0, 0.2, 1] } },
};

// Spec §4 law: orchestrated animations collapse to simple fades under
// prefers-reduced-motion. MotionConfig reducedMotion="user" alone skips the
// bundled x+opacity tweens WITHOUT settling them to final values, freezing
// both steps (entering stuck at opacity 0 / translateX(64px), exiting never
// unmounting) — so we select fade-only variants explicitly instead.
export const reducedVariants = {
  enter: { opacity: 0 },
  center: { opacity: 1, transition: { duration: 0.15, ease: "easeInOut" } },
  exit: { opacity: 0, transition: { duration: 0.1, ease: "easeInOut" } },
};
