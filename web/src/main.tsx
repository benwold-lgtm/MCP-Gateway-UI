// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import React from "react";
import { createRoot } from "react-dom/client";
// Self-hosted, not a CDN: this console is deployed into airgapped estates, and a webfont
// that silently fails to load leaves the type spec unmet with nothing to notice.
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "./index.css";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
