import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { reducedVariants, stepVariants } from "./stepMotion.js";
import lockupBanner from "../assets/brand/goat-lockup-horizontal-dark.png";
import Disclaimer from "./steps/Disclaimer.jsx";
import WalletGate from "./steps/WalletGate.jsx";
import CreateWallet from "./steps/CreateWallet.jsx";
import KeyReveal from "./steps/KeyReveal.jsx";
import ImportWallet from "./steps/ImportWallet.jsx";
import BindUsername from "./steps/BindUsername.jsx";

// Step registry.
const STEPS = {
  disclaimer: Disclaimer,
  wallet_gate: WalletGate,
  create: CreateWallet,
  key_reveal: KeyReveal,
  import: ImportWallet,
  bind_username: BindUsername,
};
const STEP_ORDER = ["disclaimer", "wallet_gate", "create", "import", "bind_username", "key_reveal"];

// T27 P1: wizard-level back navigation. No entry = no back arrow — disclaimer is
// the first step, and key_reveal is irreversible (the key was already shown;
// existing security law).
const PREV = {
  wallet_gate: "disclaimer",
  create: "wallet_gate",
  import: "wallet_gate",
  bind_username: "wallet_gate",
};

// Step-transition variants live in ./stepMotion.js (T28 R1) — shared with
// AddWalletOverlay so both surfaces keep the identical approved choreography.

export default function OnboardingWizard({ initialStep = "disclaimer", onFinished }) {
  const [step, setStep] = useState(initialStep);
  // Cross-step context: wallet meta + chosen username survive step changes.
  const [wizardCtx, setWizardCtx] = useState({});
  const reduced = useReducedMotion();
  const variants = reduced ? reducedVariants : stepVariants;

  const Step = STEPS[step] ?? Disclaimer;
  const dotIndex = Math.max(0, STEP_ORDER.indexOf(step));

  return (
    <div className="wizard">
      <div className="wizard__banner glass glass--static">
        <img src={lockupBanner} alt="GOATPROJECT — the people's compute commons" />
      </div>
      <AnimatePresence mode="popLayout">
        <motion.div
          key={step}
          className="wizard__step glass glass--static"
          variants={variants}
          initial="enter"
          animate="center"
          exit="exit"
        >
          {PREV[step] && (
            <button
              type="button"
              className="wizard-back glass"
              aria-label="Back"
              onClick={() => setStep(PREV[step])}
            >
              ←
            </button>
          )}
          <Step
            goTo={setStep}
            finish={onFinished}
            wizardCtx={wizardCtx}
            setWizardCtx={setWizardCtx}
          />
        </motion.div>
      </AnimatePresence>
      <div className="wizard__dots" aria-hidden>
        {STEP_ORDER.map((id, i) => (
          <span key={id} className={`wizard__dot ${i <= dotIndex ? "active" : ""}`} />
        ))}
      </div>
    </div>
  );
}
