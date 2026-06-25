// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Flat config (ESLint 9). Matches the standard Vite React+TS setup; prettier last
// so formatting rules don't conflict with prettier.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  { ignores: ["dist", "node_modules", "src/gateway.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // TypeScript already resolves identifiers/globals (document, fetch, ...); the core
      // rule would false-positive on browser globals without a globals config.
      "no-undef": "off",
    },
  },
  {
    // Node-run build/maintenance scripts (e.g. the spec drift checker) — declare the
    // Node globals they use so js.configs.recommended's no-undef doesn't fire.
    files: ["scripts/**/*.{js,mjs}"],
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        fetch: "readonly",
        URL: "readonly",
      },
    },
  },
  prettier,
);
