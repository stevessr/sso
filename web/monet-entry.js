// Build: cd web && npm install && npm run build:monet
// Uses Google's Material Color Utilities HCT / tonal palettes, not an HSL approximation.
import { argbFromHex, themeFromSourceColor, hexFromArgb, applyTheme } from '@material/material-color-utilities';
export function applyMonetTheme(seedHex) {
  const theme = themeFromSourceColor(argbFromHex(seedHex));
  applyTheme(theme, { target: document.documentElement, dark: window.matchMedia('(prefers-color-scheme: dark)').matches });
  const scheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? theme.schemes.dark : theme.schemes.light;
  const root = document.documentElement;
  for (const key of ['primary','onPrimary','primaryContainer','onPrimaryContainer','secondary','secondaryContainer','surface','onSurface','surfaceContainer','outline']) {
    const css = key.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`);
    const color = scheme[key];
    if (typeof color === 'number') root.style.setProperty(`--${css}`, hexFromArgb(color));
  }
}
