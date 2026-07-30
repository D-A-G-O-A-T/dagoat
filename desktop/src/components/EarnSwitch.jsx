import { EARN_SWITCH_CAPTION, EARN_SWITCH_LABEL } from "../onboarding/copy.js";

export default function EarnSwitch({ on, onChange }) {
  return (
    <div className="earn-switch">
      <div className="earn-switch__row">
        <span className="earn-switch__label">{EARN_SWITCH_LABEL}</span>
        <button
          type="button"
          role="switch"
          aria-checked={on}
          className={`earn-switch__track ${on ? "on" : ""}`}
          onClick={() => onChange(!on)}
        >
          <span className="earn-switch__thumb" />
        </button>
      </div>
      <p className="earn-switch__caption">{EARN_SWITCH_CAPTION}</p>
    </div>
  );
}
