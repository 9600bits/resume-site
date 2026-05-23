import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;
const ITERATIONS = 310000;

const options = parseArgs(process.argv.slice(2));
const inputPath = resolve(options.input || "");
const outputPath = resolve(options.output || "resume-attachment.enc.json");
const fileName = options.name || basename(inputPath);
const mimeType = options.type || "application/pdf";

if (!options.input) {
  throw new Error("Missing --input <file>.");
}

const password = options.password || await askPassword();
if (!password) {
  throw new Error("Password cannot be empty.");
}

const fileBytes = await readFile(inputPath);
const salt = webcrypto.getRandomValues(new Uint8Array(16));
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const key = await deriveKey(password, salt);
const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, fileBytes);

const payload = {
  version: 1,
  algorithm: "AES-GCM",
  kdf: "PBKDF2-SHA-256",
  iterations: ITERATIONS,
  fileName,
  mimeType,
  salt: bytesToBase64(salt),
  iv: bytesToBase64(iv),
  ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
};

await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
console.log(`Encrypted attachment written to ${outputPath}`);

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
    } else if (current === "--password") {
      parsed.password = args[index + 1];
      index += 1;
    } else if (current === "--name") {
      parsed.name = args[index + 1];
      index += 1;
    } else if (current === "--type") {
      parsed.type = args[index + 1];
      index += 1;
    }
  }
  return parsed;
}

async function askPassword() {
  const readline = createInterface({ input, output });
  const value = await readline.question("Attachment password: ");
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
