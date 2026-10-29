
// AES-GCM decryption implementation
// Based on vultisig-windows reference implementation

// Newer Vultisig apps (Android, iOS, web, extension) encrypt backups as
// "VLT\x02" || salt(16) || iv(12) || AES-256-GCM ciphertext, with the key derived by
// PBKDF2-HMAC-SHA256 (600,000 iterations). Older backups use key = SHA-256(password)
// with the 12-byte nonce in front of the ciphertext. Both are still in use.
const PBKDF2_MAGIC = [0x56, 0x4c, 0x54, 0x02];
const PBKDF2_SALT_LENGTH = 16;
const PBKDF2_IV_LENGTH = 12;
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HEADER_LENGTH = PBKDF2_MAGIC.length + PBKDF2_SALT_LENGTH + PBKDF2_IV_LENGTH;
const GCM_TAG_LENGTH = 16;

function isPbkdf2Backup(value) {
    return value.length >= PBKDF2_MAGIC.length && PBKDF2_MAGIC.every((b, i) => value[i] === b);
}

async function decryptPbkdf2({ key, value }) {
    if (value.length < PBKDF2_HEADER_LENGTH + GCM_TAG_LENGTH) {
        throw new Error('Encrypted data too short');
    }
    const salt = value.slice(PBKDF2_MAGIC.length, PBKDF2_MAGIC.length + PBKDF2_SALT_LENGTH);
    const iv = value.slice(PBKDF2_MAGIC.length + PBKDF2_SALT_LENGTH, PBKDF2_HEADER_LENGTH);
    const ciphertext = value.slice(PBKDF2_HEADER_LENGTH);

    const passwordKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(key),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    const cryptoKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    try {
        const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ciphertext);
        return new Uint8Array(decryptedBuffer);
    } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

/**
 * Decrypts a vault backup (PBKDF2 "VLT\x02" format or the older SHA-256 format)
 * @param {string} key - Password string
 * @param {Uint8Array} value - Encrypted data
 * @returns {Promise<Uint8Array>} - Decrypted data
 */
export async function decryptWithAesGcm({ key, value }) {
    if (isPbkdf2Backup(value)) {
        return decryptPbkdf2({ key, value });
    }

    // Hash the password to create a 256-bit key using SHA-256
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        hashBuffer,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // GCM nonce size is 12 bytes
    const nonceSize = 12;
    if (value.length < nonceSize) {
        throw new Error('Encrypted data too short - missing nonce');
    }

    // Extract nonce and ciphertext
    const nonce = value.slice(0, nonceSize);
    const ciphertext = value.slice(nonceSize);

    try {
        // Decrypt using AES-GCM
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
            },
            cryptoKey,
            ciphertext
        );

        return new Uint8Array(decryptedBuffer);
    } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

/**
 * Converts base64 string to Uint8Array
 * @param {string} base64String 
 * @returns {Uint8Array}
 */
export function fromBase64(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
