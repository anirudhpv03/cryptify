const algo = document.getElementById("algorithm");
const key = document.getElementById("key");
const plain = document.getElementById("plaintext");
const cipher = document.getElementById("ciphertext");
const toggleKey = document.getElementById("toggleKey");

/* ---------- PASSWORD TOGGLE ---------- */
toggleKey.addEventListener("click", () => {
  if (key.type === "password") {
    key.type = "text";
    toggleKey.classList.replace("fa-eye", "fa-eye-slash");
  } else {
    key.type = "password";
    toggleKey.classList.replace("fa-eye-slash", "fa-eye");
  }
});

/* ---------- MAIN ---------- */
async function encrypt() {
  if (!plain.value) return alert("Enter text");

  switch (algo.value) {
    case "caesar":
      cipher.value = caesar(plain.value, Number(key.value) || 0);
      break;
    case "vigenere":
      if (!key.value) return alert("Enter keyword");
      cipher.value = vigenere(plain.value, key.value, true);
      break;
    case "base64":
      cipher.value = btoa(plain.value);
      break;
    case "rot13":
      cipher.value = caesar(plain.value, 13);
      break;
    case "aes":
      if (!key.value) return alert("Password required");
      cipher.value = await aesEncrypt(plain.value, key.value);
      break;
  }
  alert("Encryption successful!");
}

async function decrypt() {
  if (!cipher.value) return alert("Enter encrypted text");

  try {
    switch (algo.value) {
      case "caesar":
        plain.value = caesar(cipher.value, 26 - Number(key.value) || 0);
        break;
      case "vigenere":
        plain.value = vigenere(cipher.value, key.value, false);
        break;
      case "base64":
        plain.value = atob(cipher.value);
        break;
      case "rot13":
        plain.value = caesar(cipher.value, 13);
        break;
      case "aes":
        plain.value = await aesDecrypt(cipher.value, key.value);
        break;
    }
    alert("Decryption successful!");
  } catch {
    alert("Decryption failed");
  }
}

/* ---------- CIPHERS ---------- */
function caesar(text, shift) {
  return text.replace(/[a-z]/gi, c => {
    let base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(
      (c.charCodeAt(0) - base + shift + 26) % 26 + base
    );
  });
}

function vigenere(text, key, enc) {
  let i = 0;
  key = key.toUpperCase();
  return text.replace(/[a-z]/gi, c => {
    let base = c <= 'Z' ? 65 : 97;
    let shift = key.charCodeAt(i++ % key.length) - 65;
    return String.fromCharCode(
      (c.charCodeAt(0) - base + (enc ? shift : -shift) + 26) % 26 + base
    );
  });
}

/* ---------- AES ---------- */
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:100000, hash:"SHA-256" },
    material,
    { name:"AES-GCM", length:256 },
    false,
    ["encrypt","decrypt"]
  );
}

async function aesEncrypt(text, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name:"AES-GCM", iv },
    key,
    enc.encode(text)
  );

  return bufToBase64(new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]));
}

async function aesDecrypt(data, password) {
  const bytes = base64ToBuf(data);
  const salt = bytes.slice(0,16);
  const iv = bytes.slice(16,28);
  const cipher = bytes.slice(28);
  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name:"AES-GCM", iv },
    key,
    cipher
  );

  return new TextDecoder().decode(decrypted);
}

/* ---------- UTIL ---------- */
function clearAll() {
  plain.value = cipher.value = "";
}

function copyText() {
  if (!cipher.value) return alert("Nothing to copy!");
  navigator.clipboard.writeText(cipher.value);
  alert("Copied!");
}
