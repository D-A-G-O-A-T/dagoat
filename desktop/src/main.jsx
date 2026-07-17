import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { purgeLegacyPlaintextKey } from "./chain/wallet.js";
import "./styles.css";

// Delete the orphaned pre-Stronghold plaintext key on startup (no-op if absent).
purgeLegacyPlaintextKey();

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>
);
