// Same SHAPE as the existing contribute switch, with its OWN class names.
//
// Reuse the rules, not the names: the existing switch's stylesheet classes carry
// retired vocabulary, `desktop/src/` is a swept tree, and the vocabulary law names CSS
// class names as well as UI strings. Referencing those classes here would import six
// banned tokens into a file this lane creates, purely to avoid writing seven CSS rules.
// The `bandwidth-switch__*` rules sit beside the originals with identical values.
import { PROXY_SWITCH_CAPTION, PROXY_SWITCH_LABEL } from "../proxy/copy.js";

export default function BandwidthSwitch({ on, disabled, onChange }) {
  return (
    <div className="bandwidth-switch">
      <div className="bandwidth-switch__row">
        <span className="bandwidth-switch__label">{PROXY_SWITCH_LABEL}</span>
        <button
          type="button"
          role="switch"
          aria-checked={on}
          aria-disabled={disabled}
          disabled={disabled}
          className={`bandwidth-switch__track ${on ? "on" : ""}`}
          onClick={() => onChange(!on)}
        >
          <span className="bandwidth-switch__thumb" />
        </button>
      </div>
      <p className="bandwidth-switch__caption">{PROXY_SWITCH_CAPTION}</p>
    </div>
  );
}
