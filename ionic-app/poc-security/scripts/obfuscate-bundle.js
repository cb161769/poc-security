'use strict';
/**
 * Post-build JavaScript obfuscation for KEYSTONE web/mobile bundle.
 *
 * Runs automatically via the `postbuild` npm lifecycle hook after `ng build`.
 * Processes all JS chunks in www/ using javascript-obfuscator v5 with
 * a configuration that is safe for Angular AOT + Ionic.
 *
 * Safe options rationale:
 *   stringArray + base64   — core feature: string literals → encoded lookup table
 *   renameGlobals: false   — Angular and Capacitor define window-level globals
 *   renameProperties: false — Angular DI resolves tokens by property name at runtime
 *   controlFlowFlattening: false — Angular change detection is structure-sensitive
 *   selfDefending: false   — adds anti-tamper wrappers that slow startup
 *
 * Files skipped:
 *   runtime.*.js   — Angular zone/bootstrap, tiny file, no app strings
 *   polyfills.*.js — browser polyfills, platform-detection code, skip for safety
 */

const JavaScriptObfuscator = require('javascript-obfuscator');
const fs   = require('fs');
const path = require('path');

const WWW = path.join(__dirname, '..', 'www');

const OPTIONS = {
  compact:                  true,
  controlFlowFlattening:    false,
  deadCodeInjection:        false,
  // ── String obfuscation (main value) ──────────────────────────────────────
  stringArray:              true,
  stringArrayEncoding:      ['base64'],
  stringArrayRotate:        true,
  stringArrayShuffle:       true,
  stringArrayThreshold:     0.8,   // 80% of literals moved to encoded array
  stringArrayCallsTransform: true, // wrap array-access calls (harder to reverse)
  splitStrings:             false, // splitting can break template literals
  // ── Identifier / property renaming — disabled for Angular compatibility ──
  renameGlobals:            false,
  renameProperties:         false,
  identifierNamesGenerator: 'mangled', // short names (a, b, c…) on top of terser
  // ── Misc ─────────────────────────────────────────────────────────────────
  simplify:                 true,
  selfDefending:            false,
  target:                   'browser',
  sourceMap:                false,
};

// Files whose names match these patterns are skipped
const SKIP = [
  /^runtime\./,
  /^polyfills\./,
];

// ── Main ─────────────────────────────────────────────────────────────────────

if (!fs.existsSync(WWW)) {
  console.error(`[obfuscate] www/ not found at ${WWW} — run ng build first`);
  process.exit(1);
}

const jsFiles = fs.readdirSync(WWW)
  .filter(f => f.endsWith('.js'))
  .map(f => path.join(WWW, f));

const t0 = Date.now();
let ok = 0, skipped = 0, failed = 0;
let totalBefore = 0, totalAfter = 0;

console.log(`\n[obfuscate] Processing ${jsFiles.length} JS files in www/\n`);

for (const file of jsFiles) {
  const name = path.basename(file);

  if (SKIP.some(rx => rx.test(name))) {
    console.log(`  skip     ${name}`);
    skipped++;
    continue;
  }

  const src = fs.readFileSync(file, 'utf8');
  totalBefore += src.length;

  try {
    const result = JavaScriptObfuscator.obfuscate(src, OPTIONS);
    const out = result.getObfuscatedCode();
    totalAfter += out.length;
    fs.writeFileSync(file, out, 'utf8');
    const ratio = ((out.length / src.length) * 100).toFixed(0);
    console.log(`  obfsc    ${name.padEnd(50)} ${(src.length / 1024).toFixed(1).padStart(7)} kB → ${(out.length / 1024).toFixed(1).padStart(7)} kB  (${ratio}%)`);
    ok++;
  } catch (e) {
    console.error(`  ERROR    ${name}: ${e.message}`);
    failed++;
  }
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
const overhead = (((totalAfter - totalBefore) / totalBefore) * 100).toFixed(0);

console.log(`
[obfuscate] Done in ${elapsed}s
  Obfuscated : ${ok} files
  Skipped    : ${skipped} files (runtime + polyfills)
  Errors     : ${failed} files
  Size change: ${(totalBefore / 1024).toFixed(0)} kB → ${(totalAfter / 1024).toFixed(0)} kB  (+${overhead}% overhead from string array decoder)
`);

if (failed > 0) process.exit(1);
