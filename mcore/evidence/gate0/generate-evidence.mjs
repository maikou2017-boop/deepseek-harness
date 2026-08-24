#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const PINNED_SHA = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e";
const DSH_PACKAGE = "@deepseek-ai/dsh@0.1.1-rc.2";
const root = process.cwd();
const runId = process.env.GITHUB_RUN_ID || "local";
const outDir = path.resolve(process.env.MCORE_GATE0_EVIDENCE_DIR || `mcore-evidence/gate0-${runId}`);
mkdirSync(outDir, { recursive: true });

function run(command, args = []) {
  return execFileSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, DSH_TOOLS_MODE: "native" }
  }).trim();
}

function sha256Buffer(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256File(relativePath) {
  return sha256Buffer(readFileSync(path.join(root, relativePath)));
}

function writeJson(name, value) {
  writeFileSync(path.join(outDir, name), `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function npmView(field) {
  const raw = run("npm", ["view", DSH_PACKAGE, field, "--json"]);
  try {
    return JSON.parse(raw);
  } catch {
    return raw.replace(/^"|"$/g, "");
  }
}

function collectPackageManifests(directory, output = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "node_modules", "dist", "build", "coverage", "mcore-evidence"].includes(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      collectPackageManifests(full, output);
      continue;
    }
    if (entry.name !== "package.json") continue;
    const relative = path.relative(root, full).replaceAll(path.sep, "/");
    const pkg = JSON.parse(readFileSync(full, "utf8"));
    output.push({
      path: relative,
      name: pkg.name || null,
      version: pkg.version || null,
      license: pkg.license || null,
      private: Boolean(pkg.private),
      packageManager: pkg.packageManager || null
    });
  }
  return output;
}

const changedPaths = run("git", ["diff", "--name-only", `${PINNED_SHA}..HEAD`])
  .split("\n")
  .map((value) => value.trim())
  .filter(Boolean);
const allowedPrefixes = [".github/workflows/mcore-gate0-evidence.yml", "mcore/evidence/gate0/"];
const unexpectedPaths = changedPaths.filter((value) => !allowedPrefixes.some((prefix) => value === prefix || value.startsWith(prefix)));
if (unexpectedPaths.length) {
  throw new Error(`Gate 0 branch changes upstream source files: ${unexpectedPaths.join(", ")}`);
}

const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const mergeBase = run("git", ["merge-base", "HEAD", PINNED_SHA]);
if (mergeBase !== PINNED_SHA) throw new Error(`Pinned upstream SHA is not the branch base: ${mergeBase}`);
if (pkg.version !== "0.1.1-rc.2") throw new Error(`Unexpected repository version: ${pkg.version}`);
if (pkg.packageManager !== "pnpm@11.7.0") throw new Error(`Unexpected package manager: ${pkg.packageManager}`);

const cliVersion = run("pnpm", ["dsh", "--version"]);
const npmVersion = npmView("version");
if (String(npmVersion) !== "0.1.1-rc.2") throw new Error(`Unexpected npm package version: ${npmVersion}`);

const sourceHashes = {
  licenseSha256: sha256File("LICENSE"),
  thirdPartyNoticesSha256: sha256File("THIRD_PARTY_NOTICES.md"),
  pnpmLockSha256: sha256File("pnpm-lock.yaml"),
  packageJsonSha256: sha256File("package.json")
};

const sbom = {
  schema: "mcore-minimal-workspace-sbom/v1",
  generatedFromPinnedSource: PINNED_SHA,
  rootPackage: { name: pkg.name, version: pkg.version, license: pkg.license, packageManager: pkg.packageManager },
  packages: collectPackageManifests(root).sort((a, b) => a.path.localeCompare(b.path))
};
writeJson("sbom.minimal.json", sbom);
const sbomSha256 = sha256File(path.relative(root, path.join(outDir, "sbom.minimal.json")));

const manifest = {
  schema: "mcore-dsh-gate0-manifest/v1",
  status: "REVIEW_PENDING",
  officialUpstream: "https://github.com/deepseek-ai/deepseek-harness",
  controlledFork: "https://github.com/maikou2017-boop/deepseek-harness",
  pinnedUpstreamSha: PINNED_SHA,
  branchHeadSha: run("git", ["rev-parse", "HEAD"]),
  mergeBaseSha: mergeBase,
  repositoryVersion: pkg.version,
  npmPackage: DSH_PACKAGE,
  npmResolvedVersion: npmVersion,
  npmDistIntegrity: npmView("dist.integrity"),
  npmDistTarball: npmView("dist.tarball"),
  cliVersion,
  environment: {
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    node: process.version,
    npm: run("npm", ["--version"]),
    pnpm: run("pnpm", ["--version"]),
    toolsMode: "native"
  },
  changedPaths,
  sourceHashes,
  sbomSha256,
  prohibitions: [
    "no Cordis core modification",
    "no paid or silent-fallback provider",
    "no production secrets or business data",
    "no real email, publication, deployment, payment, trading or chain write",
    "RuntimeCompleted is not MCore VERIFIED"
  ]
};
writeJson("pinned-version-manifest.json", manifest);

const rollback = `# Reproduce and rollback\n\n## Clean source reproduction\n\n\`\`\`bash\ngit clone https://github.com/maikou2017-boop/deepseek-harness.git\ncd deepseek-harness\ngit checkout ${PINNED_SHA}\ncorepack enable\ncorepack prepare pnpm@11.7.0 --activate\npnpm install --frozen-lockfile --ignore-scripts\npnpm dsh --version\n\`\`\`\n\n## Package identity check\n\n\`\`\`bash\nnpm view ${DSH_PACKAGE} version dist.integrity dist.tarball --json\n\`\`\`\n\n## Rollback / failback\n\n\`\`\`bash\ngit reset --hard ${PINNED_SHA}\ncorepack prepare pnpm@11.7.0 --activate\npnpm install --frozen-lockfile --ignore-scripts\n\`\`\`\n\nFail back immediately when the pinned package cannot reproduce its CLI identity, integrity hashes differ, plugin initialization fails, \`run_code\` is exposed while native-only mode is required, or any paid/silent-fallback provider is observed.\n`;
writeFileSync(path.join(outDir, "reproduce-rollback.md"), rollback, "utf8");

const summary = `# M4-R02 Gate 0 reviewer summary\n\n- State: **REVIEW PENDING**\n- Pinned source: \`${PINNED_SHA}\`\n- Package: \`${DSH_PACKAGE}\`\n- CLI marker: \`${cliVersion.replaceAll("`", "'")}\`\n- Tools mode: \`native\`\n- Upstream source modifications: **none**\n- Gate A/B/C/D/E/F authorization: **none**\n\nThis package proves version and supply-chain identity only. It does not claim Standalone compatibility, sandbox security, MCore integration, business Golden Path completion, or production readiness.\n`;
writeFileSync(path.join(outDir, "review-summary.md"), summary, "utf8");

const evidenceFiles = readdirSync(outDir)
  .filter((name) => name !== "evidence-index.json" && name !== "evidence-index.sha256")
  .sort()
  .map((name) => {
    const filePath = path.join(outDir, name);
    if (!statSync(filePath).isFile()) return null;
    return { name, bytes: statSync(filePath).size, sha256: sha256Buffer(readFileSync(filePath)) };
  })
  .filter(Boolean);
writeJson("evidence-index.json", { schema: "mcore-evidence-index/v1", status: "REVIEW_PENDING", files: evidenceFiles });
const indexHash = sha256Buffer(readFileSync(path.join(outDir, "evidence-index.json")));
writeFileSync(path.join(outDir, "evidence-index.sha256"), `${indexHash}  evidence-index.json\n`, "utf8");

console.log(JSON.stringify({ ok: true, status: "REVIEW_PENDING", outDir: path.relative(root, outDir), indexSha256: indexHash }, null, 2));
