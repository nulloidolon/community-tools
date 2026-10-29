import assert from "node:assert/strict";
import { decryptWithAesGcm, fromBase64 } from "../web/aes_gcm.js";

// Backup vectors produced by the iOS, web and extension clients
// (vultisig-android: data/src/test/resources/ios-backup-vectors).
const pbkdf2Vectors = [
  { name: "ios", password: "ios-backup-test", plaintext: "ios-vault-data-abc", ciphertext: "VkxUAhEREREREREREREREREREREiIiIiIiIiIiIiIiKkVKfBB781udjJZHri5f/jKie5Xsb4+QMQYZXgRTguEaj9" },
  { name: "web", password: "web-backup-test", plaintext: "web-vault-data-123", ciphertext: "VkxUAlVVVVVVVVVVVVVVVVVVVVVmZmZmZmZmZmZmZmZr4T5NonTmP8O9liQ+wr3stndn68X5KkNDL2uuXdQCsSTO" },
  { name: "extension", password: "ext-backup-test", plaintext: "extension-vault-data-xyz", ciphertext: "VkxUAjMzMzMzMzMzMzMzMzMzMzNERERERERERERERESValWh59NN5UIkkUqX4A+zulYM8mK8YPoD507DzKedPieXIywb8OeX" },
];

const text = (bytes) => new TextDecoder().decode(bytes);

for (const v of pbkdf2Vectors) {
  const value = fromBase64(v.ciphertext);
  assert.equal(text(await decryptWithAesGcm({ key: v.password, value })), v.plaintext, `${v.name} vector`);
  await assert.rejects(decryptWithAesGcm({ key: v.password + "x", value }), `${v.name}: wrong password must fail`);
}

// Older backups: key = SHA-256(password), 12-byte nonce in front.
{
  const password = "legacy-pass";
  const plaintext = "legacy vault bytes";
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));
  const key = await crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plaintext)));
  const value = new Uint8Array([...nonce, ...sealed]);
  assert.equal(text(await decryptWithAesGcm({ key: password, value })), plaintext, "legacy backup");
}

await assert.rejects(
  decryptWithAesGcm({ key: "x", value: new Uint8Array([0x56, 0x4c, 0x54, 0x02, ...new Uint8Array(10)]) }),
  "short PBKDF2 payload must fail",
);

console.log("aes_gcm tests passed");
