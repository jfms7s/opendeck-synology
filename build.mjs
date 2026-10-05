#!/usr/bin/env node
// Packages the plugin: dist/<uuid>.sdPlugin/ (assets + one binary per target),
// zipped as dist/<name>.streamDeckPlugin, with dist/SHA256SUMS.
//
// Usage:
//   node build.mjs                    every target in the manifest's CodePaths that has
//                                     a release binary (`cargo build --release [--target T]`)
//   node build.mjs <triple>...        only these targets
//   node build.mjs --require-all      fail unless every CodePaths target was built (releases)
//   node build.mjs --tag v1.2.3       also check the release tag against the version
//   node build.mjs --check-version    only check that Cargo.toml and manifest.json agree (CI)
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, cpSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const UUID = "com.jfms7s.synology";
const BIN_NAME = "opendeck-synology";

function fail(msg) {
	console.error(msg);
	process.exit(1);
}

const args = process.argv.slice(2);
const flag = (name) => {
	const i = args.indexOf(name);
	if (i === -1) return false;
	args.splice(i, 1);
	return true;
};
const option = (name) => {
	const i = args.indexOf(name);
	if (i === -1) return null;
	const value = args[i + 1];
	if (!value) fail(`${name} needs a value`);
	args.splice(i, 2);
	return value;
};
const checkOnly = flag("--check-version");
const requireAll = flag("--require-all");
const tag = option("--tag");
const unknown = args.find((a) => a.startsWith("-"));
if (unknown) fail(`unknown option ${unknown}`);

// Cargo.toml's [package] version and manifest.json's "Version" have nothing
// keeping them in sync - catch drift here rather than shipping a plugin
// whose crate version and Elgato-facing manifest version disagree.
const cargoToml = readFileSync("Cargo.toml", "utf8");
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!cargoVersion) fail('could not find `version = "..."` in Cargo.toml');
const manifest = JSON.parse(readFileSync("assets/manifest.json", "utf8"));
if (cargoVersion !== manifest.Version) {
	fail(`version mismatch: Cargo.toml is ${cargoVersion} but assets/manifest.json is ${manifest.Version} - bump them together`);
}
if (tag !== null && tag.replace(/^v/, "") !== cargoVersion) {
	fail(`release tag ${tag} does not match version ${cargoVersion}`);
}
if (checkOnly) {
	console.log(`version ${cargoVersion} matches in Cargo.toml and assets/manifest.json`);
	process.exit(0);
}

const codePaths = manifest.CodePaths || {};
for (const key of ["CodePathLin", "CodePathMac"]) {
	if (manifest[key] && !Object.values(codePaths).includes(manifest[key])) {
		fail(`assets/manifest.json ${key} ${manifest[key]} is not one of its CodePaths`);
	}
}
const host = execFileSync("rustc", ["-vV"], { encoding: "utf8" }).match(/^host: (\S+)/m)?.[1];

// The newest release binary for a target: `--target <triple>` builds land in
// target/<triple>/release, a plain build for the host in target/release.
function binaryFor(triple) {
	const candidates = [join("target", triple, "release", BIN_NAME)];
	if (triple === host) candidates.push(join("target", "release", BIN_NAME));
	return candidates
		.filter((p) => existsSync(p))
		.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
}

for (const triple of args) {
	if (!(triple in codePaths)) fail(`${triple} is not in assets/manifest.json CodePaths`);
}
const wanted = args.length > 0 ? args : Object.keys(codePaths);
const built = wanted.map((triple) => [triple, binaryFor(triple)]);
const missing = built.filter(([, bin]) => !bin).map(([triple]) => triple);
if ((args.length > 0 || requireAll) && missing.length > 0) {
	fail(`missing release binaries for ${missing.join(", ")} (run: cargo build --release --locked --target <triple>)`);
}
const targets = built.filter(([, bin]) => bin);
if (targets.length === 0) fail("no release binary found (run: cargo build --release --locked)");

const outDir = join("dist", `${UUID}.sdPlugin`);
rmSync("dist", { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

cpSync("assets/manifest.json", join(outDir, "manifest.json"));
// Not every plugin has layouts or a property inspector - copy what exists.
// Icon sources (assets/icon-src/) are deliberately not shipped.
for (const dir of ["icons", "layouts", "propertyInspector"]) {
	if (existsSync(join("assets", dir))) {
		cpSync(join("assets", dir), join(outDir, dir), { recursive: true });
	}
}
for (const [triple, bin] of targets) {
	const dest = join(outDir, codePaths[triple]);
	copyFileSync(bin, dest);
	chmodSync(dest, 0o755);
	console.log(`added ${bin} as ${codePaths[triple]}`);
}
if (missing.length > 0) console.warn(`not built, left out: ${missing.join(", ")}`);

const bundle = `${BIN_NAME}.streamDeckPlugin`;
const zip = spawnSync("zip", ["-q", "-r", "-X", bundle, `${UUID}.sdPlugin`], { cwd: "dist", stdio: "inherit" });
if (zip.error || zip.status !== 0) fail(`zip failed${zip.error ? `: ${zip.error.message}` : ""} (is \`zip\` installed?)`);

const sum = createHash("sha256").update(readFileSync(join("dist", bundle))).digest("hex");
writeFileSync(join("dist", "SHA256SUMS"), `${sum}  ${bundle}\n`);
console.log(`built dist/${bundle} (${targets.map(([t]) => t).join(", ")}), sha256 ${sum}`);
