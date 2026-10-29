// Cargo runner for wasm32-wasip1: runs a wasm binary under Node's WASI (V8, the engine Workers use).
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const [file, ...args] = process.argv.slice(2);
const wasi = new WASI({ version: "preview1", args: [file, ...args], env: process.env, returnOnExit: true });
const { instance } = await WebAssembly.instantiate(await readFile(file), wasi.getImportObject());
process.exitCode = wasi.start(instance);
