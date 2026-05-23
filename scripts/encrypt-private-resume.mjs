import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { readFile, writeFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { resolve } from "node:path";

const { subtle } = webcrypto;
const ITERATIONS = 310000;

const options = parseArgs(process.argv.slice(2));
const inputPath = resolve(options.input || "private-resume.json");
const outputPath = resolve(options.output || "private-resume.enc.json");

const password = await askPassword();
if (!password) {
  throw new Error("Password cannot be empty.");
}

const plaintext = await readFile(inputPath);
JSON.parse(plaintext.toString("utf8"));

const salt = webcrypto.getRandomValues(new Uint8Array(16));
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const key = await deriveKey(password, salt);
const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

const payload = {
  version: 1,
  algorithm: "AES-GCM",
  kdf: "PBKDF2-SHA-256",
  iterations: ITERATIONS,
  salt: bytesToBase64(salt),
  iv: bytesToBase64(iv),
  ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
};

await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
await updateEmbeddedPayload(payload);
console.log(`Encrypted private resume written to ${outputPath}`);

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === "--input" || current === "-i") {
      parsed.input = args[index + 1];
      index += 1;
    } else if (current === "--output" || current === "-o") {
      parsed.output = args[index + 1];
      index += 1;
    }
  }
  return parsed;
}

async function askPassword() {
  const readline = createInterface({ input, output });
  const value = await readline.question("Access password: ");
  readline.close();
  return value;
}

async function deriveKey(password, salt) {
  const keyMaterial = await subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
}

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function updateEmbeddedPayload(payload) {
  const indexPath = resolve("index.html");
  let html;
  try {
    html = await readFile(indexPath, "utf8");
  } catch {
    return;
  }

  const payloadBlock = [
    '<script type="application/json" id="encrypted-resume-data">',
    JSON.stringify(payload, null, 2),
    "</script>",
  ].join("\n");

  const existing = /<script type="application\/json" id="encrypted-resume-data">[\s\S]*?<\/script>/;
  const nextHtml = existing.test(html)
    ? html.replace(existing, payloadBlock)
    : html.replace('  <script src="assets/app.js" defer></script>', `  ${payloadBlock}\n  <script src="assets/app.js" defer></script>`);

  if (nextHtml !== html) {
    await writeFile(indexPath, nextHtml, "utf8");
  }
}
