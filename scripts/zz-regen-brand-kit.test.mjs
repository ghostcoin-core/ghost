import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

test("regenerate", () => {
  const out = execFileSync(fileURLToPath(new URL("./build-brand-kit.sh", import.meta.url)), [], { encoding: "utf8", stdio: "pipe" });
  console.log(out);
});
