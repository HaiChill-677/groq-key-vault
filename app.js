(() => {
  "use strict";

  const GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models";
  const STORAGE_THEME_KEY = "groq_vault_theme";
  const STORAGE_RR_KEY = "groq_vault_rr_index";
  const DEFAULT_GITHUB_PLACEHOLDER = "https://<username>.github.io/<repo>/keys.json";

  const state = {
    rawVault: null,
    mode: "open", // "open" | "encrypted"
    locked: false,
    items: [], // { id, label, value (decoded gsk_...), active, revealed, testStatus, testDetail }
    filter: "all",
    search: "",
    revealAll: false,
    pickedKey: null,
    pickedRevealed: false,
    guideTab: "python",
    guideMode: "open",
    exportMode: "open",
    customGuideUrl: "",
  };

  const els = {
    modeBadge: document.getElementById("mode-badge"),
    themeToggle: document.getElementById("theme-toggle"),
    reloadBtn: document.getElementById("reload-btn"),
    sourceNotice: document.getElementById("source-notice"),
    updatedAt: document.getElementById("updated-at"),
    statTotal: document.getElementById("stat-total"),
    statActive: document.getElementById("stat-active"),
    statState: document.getElementById("stat-state"),
    endpointPreview: document.getElementById("endpoint-preview"),
    copyEndpointBtn: document.getElementById("copy-endpoint-btn"),
    pickRoundRobinBtn: document.getElementById("pick-round-robin-btn"),
    pickRandomBtn: document.getElementById("pick-random-btn"),
    testAllBtn: document.getElementById("test-all-btn"),
    copyEnvBtn: document.getElementById("copy-env-btn"),
    copyJsonBtn: document.getElementById("copy-json-btn"),
    pickedStrip: document.getElementById("picked-strip"),
    pickedLabel: document.getElementById("picked-label"),
    pickedValue: document.getElementById("picked-value"),
    pickedToggleBtn: document.getElementById("picked-toggle-btn"),
    pickedCopyBtn: document.getElementById("picked-copy-btn"),
    unlockFrame: document.getElementById("unlock-frame"),
    unlockForm: document.getElementById("unlock-form"),
    unlockPassphrase: document.getElementById("unlock-passphrase"),
    unlockToggleVis: document.getElementById("unlock-toggle-vis"),
    unlockError: document.getElementById("unlock-error"),
    vaultFrame: document.getElementById("vault-frame"),
    toggleAllVisibilityBtn: document.getElementById("toggle-all-visibility-btn"),
    searchInput: document.getElementById("search-input"),
    keyList: document.getElementById("key-list"),
    guideUrlInput: document.getElementById("guide-url-input"),
    guideUrlReset: document.getElementById("guide-url-reset"),
    copyGuideCodeBtn: document.getElementById("copy-guide-code-btn"),
    codeGuideBody: document.getElementById("code-guide-body"),
    addKeyForm: document.getElementById("add-key-form"),
    newKeyInput: document.getElementById("new-key-input"),
    newKeyLabel: document.getElementById("new-key-label"),
    exportPassphraseRow: document.getElementById("export-passphrase-row"),
    exportPassphrase: document.getElementById("export-passphrase"),
    exportPassphraseConfirm: document.getElementById("export-passphrase-confirm"),
    downloadJsonBtn: document.getElementById("download-json-btn"),
    copyExportJsonBtn: document.getElementById("copy-export-json-btn"),
    importJsonInput: document.getElementById("import-json-input"),
    resetSessionBtn: document.getElementById("reset-session-btn"),
    manageFeedback: document.getElementById("manage-feedback"),
    toast: document.getElementById("toast"),
  };

  let toastTimer = null;

  function showToast(message) {
    els.toast.textContent = message;
    els.toast.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      els.toast.classList.add("hidden");
    }, 2400);
  }

  function showNotice(message) {
    if (!message) {
      els.sourceNotice.classList.add("hidden");
      els.sourceNotice.textContent = "";
      return;
    }
    els.sourceNotice.textContent = message;
    els.sourceNotice.classList.remove("hidden");
  }

  function setManageFeedback(message) {
    if (!message) {
      els.manageFeedback.classList.add("hidden");
      els.manageFeedback.textContent = "";
      return;
    }
    els.manageFeedback.textContent = message;
    els.manageFeedback.classList.remove("hidden");
  }

  function encodeRevB64(plain) {
    return btoa(plain.split("").reverse().join(""));
  }

  function decodeRevB64(encoded) {
    return atob(encoded).split("").reverse().join("");
  }

  function bytesToB64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }

  async function deriveAesKey(passphrase, salt, iterations) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Trình duyệt không hỗ trợ Web Crypto API trên ngữ cảnh hiện tại (hãy dùng HTTPS hoặc localhost).");
    }
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function decryptVaultPayload(vault, passphrase) {
    const salt = b64ToBytes(vault.salt);
    const iv = b64ToBytes(vault.iv);
    const payload = b64ToBytes(vault.payload);
    const iterations = Number(vault.iterations) || 200000;
    const aesKey = await deriveAesKey(passphrase, salt, iterations);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      payload
    );
    return JSON.parse(new TextDecoder().decode(plainBuffer));
  }

  async function encryptVaultItems(items, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const iterations = 200000;
    const aesKey = await deriveAesKey(passphrase, salt, iterations);
    const serialized = JSON.stringify(
      items.map((item) => ({
        id: item.id,
        label: item.label,
        value: item.value,
        active: item.active,
      }))
    );
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      new TextEncoder().encode(serialized)
    );
    return {
      version: 1,
      provider: "groq",
      mode: "encrypted",
      kdf: "PBKDF2-SHA256",
      iterations,
      cipher: "AES-256-GCM",
      updatedAt: new Date().toISOString(),
      salt: bytesToB64(salt),
      iv: bytesToB64(iv),
      payload: bytesToB64(new Uint8Array(encryptedBuffer)),
    };
  }

  function maskKey(key) {
    if (!key || key.length < 14) return "••••••••";
    return `${key.slice(0, 8)}••••••••••••••••••••••${key.slice(-5)}`;
  }

  function resolveEndpointUrl() {
    if (window.location.protocol === "http:" || window.location.protocol === "https:") {
      return new URL("./keys.json", window.location.href).href;
    }
    return DEFAULT_GITHUB_PLACEHOLDER;
  }

  function getActiveGuideUrl() {
    const val = els.guideUrlInput.value.trim();
    return val || resolveEndpointUrl();
  }

  function applyTheme(theme) {
    const next = theme === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem(STORAGE_THEME_KEY, next);
    els.themeToggle.textContent = next === "dark" ? "Giao diện: Tối" : "Giao diện: Sáng";
  }

  function initTheme() {
    const saved = localStorage.getItem(STORAGE_THEME_KEY);
    if (saved === "dark" || saved === "light") {
      applyTheme(saved);
      return;
    }
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(prefersDark ? "dark" : "light");
  }

  async function copyText(text, successMsg) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      showToast(successMsg || "Đã sao chép vào clipboard.");
    } catch {
      showToast("Không thể truy cập clipboard — hãy sao chép thủ công.");
    }
  }

  function normalizeDecodedItems(rawItems, encoding) {
    return (rawItems || []).map((item, idx) => {
      let decoded = item.value || "";
      if (encoding === "rev-b64" && !decoded.startsWith("gsk_")) {
        decoded = decodeRevB64(decoded);
      }
      return {
        id: item.id || `key-${String(idx + 1).padStart(2, "0")}`,
        label: item.label || `Groq Key #${String(idx + 1).padStart(2, "0")}`,
        value: decoded,
        active: item.active !== false,
        revealed: false,
        testStatus: "untested", // untested | ok | ratelimit | invalid | error
        testDetail: "",
      };
    });
  }

  function loadVaultObject(vault, sourceLabel) {
    state.rawVault = vault;
    state.mode = vault.mode === "encrypted" ? "encrypted" : "open";
    state.pickedKey = null;
    els.pickedStrip.classList.add("hidden");
    els.unlockError.classList.add("hidden");

    if (state.mode === "encrypted") {
      state.locked = true;
      state.items = [];
      state.guideMode = "encrypted";
      state.exportMode = "encrypted";
      syncSegmentedActive("[data-guide-mode]", "guideMode", "encrypted");
      syncSegmentedActive("[data-export-mode]", "exportMode", "encrypted");
      els.exportPassphraseRow.classList.remove("hidden");
    } else {
      state.locked = false;
      state.items = normalizeDecodedItems(vault.items, vault.encoding);
      state.guideMode = "open";
      state.exportMode = "open";
      syncSegmentedActive("[data-guide-mode]", "guideMode", "open");
      syncSegmentedActive("[data-export-mode]", "exportMode", "open");
      els.exportPassphraseRow.classList.add("hidden");
    }

    if (sourceLabel) {
      showNotice(sourceLabel);
    } else {
      showNotice("");
    }

    renderAll();
  }

  async function loadVaultFromRepo() {
    showNotice("");
    if (window.location.protocol === "file:") {
      if (window.__GROQ_VAULT_FALLBACK__) {
        loadVaultObject(
          window.__GROQ_VAULT_FALLBACK__,
          "Đang mở trực tiếp qua file:// — dùng dữ liệu từ keys-fallback.js. Khi chạy qua HTTP hoặc GitHub Pages, trang sẽ tự fetch trực tiếp tệp keys.json."
        );
        return;
      }
    }

    try {
      const res = await fetch(`./keys.json?t=${Date.now()}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const vault = await res.json();
      loadVaultObject(vault, "");
    } catch (err) {
      if (window.__GROQ_VAULT_FALLBACK__) {
        loadVaultObject(
          window.__GROQ_VAULT_FALLBACK__,
          `Không thể fetch ./keys.json (${err.message}) — đang hiển thị bản dự phòng cục bộ.`
        );
      } else {
        showNotice(`Không thể đọc keys.json: ${err.message}`);
        state.items = [];
        renderAll();
      }
    }
  }

  function syncSegmentedActive(selector, attr, value) {
    document.querySelectorAll(selector).forEach((btn) => {
      const key = attr === "guideMode" ? "guideMode" : "exportMode";
      btn.classList.toggle("is-active", btn.dataset[key] === value);
    });
  }

  function getFilteredItems() {
    const q = state.search.trim().toLowerCase();
    return state.items.filter((item) => {
      if (state.filter === "active" && (!item.active || item.testStatus === "invalid")) {
        return false;
      }
      if (state.filter === "inactive" && item.active && item.testStatus !== "invalid" && item.testStatus !== "ratelimit") {
        return false;
      }
      if (!q) return true;
      return (
        item.label.toLowerCase().includes(q) ||
        item.value.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q)
      );
    });
  }

  function renderOverview() {
    const total = state.items.length;
    const activeCount = state.items.filter((k) => k.active && k.testStatus !== "invalid").length;

    els.modeBadge.textContent = state.mode === "encrypted" ? "AES-256-GCM" : "Open (rev-b64)";
    els.updatedAt.textContent =
      state.rawVault && state.rawVault.updatedAt
        ? `Cập nhật: ${state.rawVault.updatedAt.replace("T", " ").replace("Z", " UTC")}`
        : "";

    if (state.locked) {
      els.statTotal.textContent = "••";
      els.statActive.textContent = "••";
      els.statState.textContent = "Đã khóa";
    } else {
      els.statTotal.textContent = String(total);
      els.statActive.textContent = String(activeCount);
      els.statState.textContent = state.mode === "encrypted" ? "Đã giải mã" : "Sẵn sàng";
    }

    const endpoint = resolveEndpointUrl();
    els.endpointPreview.value = endpoint;
    if (!state.customGuideUrl) {
      els.guideUrlInput.value = endpoint;
    }

    const disabledActions = state.locked || activeCount === 0;
    els.pickRoundRobinBtn.disabled = disabledActions;
    els.pickRandomBtn.disabled = disabledActions;
    els.testAllBtn.disabled = state.locked || total === 0;
    els.copyEnvBtn.disabled = state.locked || total === 0;
    els.copyJsonBtn.disabled = state.locked || total === 0;

    if (state.locked) {
      els.unlockFrame.classList.remove("hidden");
      els.vaultFrame.classList.add("hidden");
    } else {
      els.unlockFrame.classList.add("hidden");
      els.vaultFrame.classList.remove("hidden");
    }
  }

  function statusBadgeHtml(item) {
    if (!item.active) {
      return `<span class="pill pill-dashed"><span class="dot dot-hollow"></span>Tạm tắt</span>`;
    }
    switch (item.testStatus) {
      case "testing":
        return `<span class="pill pill-outline"><span class="dot dot-half"></span>Đang kiểm tra...</span>`;
      case "ok":
        return `<span class="pill pill-outline"><span class="dot dot-solid"></span>Hợp lệ • ${escapeHtml(item.testDetail)}</span>`;
      case "ratelimit":
        return `<span class="pill pill-outline"><span class="dot dot-half"></span>Rate limit (429)</span>`;
      case "invalid":
        return `<span class="pill pill-dashed"><span class="dot dot-hollow"></span>Không hợp lệ (401)</span>`;
      case "error":
        return `<span class="pill pill-outline"><span class="dot dot-half"></span>${escapeHtml(item.testDetail || "Lỗi kiểm tra")}</span>`;
      default:
        return `<span class="pill pill-outline"><span class="dot dot-solid"></span>Hoạt động</span>`;
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderKeyList() {
    if (state.locked) return;

    const list = getFilteredItems();
    els.toggleAllVisibilityBtn.textContent = state.revealAll ? "Ẩn tất cả" : "Hiện tất cả";

    if (list.length === 0) {
      els.keyList.innerHTML = `<div class="empty-state">Không tìm thấy key nào phù hợp bộ lọc hiện tại.</div>`;
      return;
    }

    els.keyList.innerHTML = list
      .map((item) => {
        const idxNumber = state.items.indexOf(item) + 1;
        const idxLabel = `#${String(idxNumber).padStart(2, "0")}`;
        const shown = state.revealAll || item.revealed;
        const displayVal = shown ? item.value : maskKey(item.value);
        return `
          <article class="key-card ${item.active ? "" : "is-inactive"}" data-id="${escapeHtml(item.id)}">
            <div class="key-card-top">
              <div class="key-identity">
                <span class="key-index">${idxLabel}</span>
                <input
                  class="key-label-input"
                  type="text"
                  value="${escapeHtml(item.label)}"
                  data-action="rename"
                  aria-label="Tên nhãn của key ${idxLabel}"
                />
                ${statusBadgeHtml(item)}
              </div>
              <div class="key-actions">
                <button type="button" class="btn btn-secondary btn-xs" data-action="toggle-vis">
                  ${shown ? "Ẩn" : "Hiện"}
                </button>
                <button type="button" class="btn btn-primary btn-xs" data-action="copy">
                  Chép
                </button>
                <button type="button" class="btn btn-secondary btn-xs" data-action="test">
                  Test
                </button>
                <button type="button" class="btn btn-secondary btn-xs" data-action="toggle-active">
                  ${item.active ? "Tắt" : "Bật"}
                </button>
                <button type="button" class="btn btn-secondary btn-xs" data-action="delete">
                  Xóa
                </button>
              </div>
            </div>
            <div class="key-card-bottom">
              <code class="key-value">${escapeHtml(displayVal)}</code>
            </div>
          </article>
        `;
      })
      .join("");
  }

  function renderPickedStrip() {
    if (!state.pickedKey) {
      els.pickedStrip.classList.add("hidden");
      return;
    }
    els.pickedStrip.classList.remove("hidden");
    els.pickedLabel.textContent = state.pickedKey.label;
    els.pickedValue.textContent = state.pickedRevealed
      ? state.pickedKey.value
      : maskKey(state.pickedKey.value);
    els.pickedToggleBtn.textContent = state.pickedRevealed ? "Ẩn" : "Hiện";
  }

  function getCodeSnippet(tab, mode, url) {
    if (tab === "python") {
      if (mode === "encrypted") {
        return `import base64
import json
import os
import random
import urllib.request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Cài đặt thư viện giải mã: pip install cryptography
VAULT_URL = "${url}"
PASSPHRASE = os.environ["VAULT_PASSPHRASE"]  # Đặt biến môi trường trước khi chạy

def fetch_groq_keys(url: str = VAULT_URL, passphrase: str = PASSPHRASE) -> list[str]:
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=10) as res:
        vault = json.loads(res.read().decode("utf-8"))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(vault["salt"]),
        iterations=vault["iterations"],
    )
    aes_key = kdf.derive(passphrase.encode("utf-8"))
    plaintext = AESGCM(aes_key).decrypt(
        base64.b64decode(vault["iv"]),
        base64.b64decode(vault["payload"]),
        None,
    )
    items = json.loads(plaintext.decode("utf-8"))
    return [item["value"] for item in items if item.get("active", True)]

if __name__ == "__main__":
    keys = fetch_groq_keys()
    api_key = random.choice(keys)
    print(f"Đã lấy {len(keys)} key. Ví dụ prefix: {api_key[:8]}...")`;
      }

      return `import base64
import json
import random
import urllib.error
import urllib.request

# Không cần cài thêm thư viện ngoài (dùng Python chuẩn)
VAULT_URL = "${url}"

def fetch_groq_keys(url: str = VAULT_URL) -> list[str]:
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=10) as res:
        data = json.loads(res.read().decode("utf-8"))

    return [
        base64.b64decode(item["value"]).decode("utf-8")[::-1]
        for item in data.get("items", [])
        if item.get("active", True)
    ]

def chat_groq(prompt: str, model: str = "llama-3.3-70b-versatile") -> str:
    keys = fetch_groq_keys()
    random.shuffle(keys)

    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    for api_key in keys:
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "groq-vault-client/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                result = json.loads(res.read().decode("utf-8"))
                return result["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as err:
            if err.code == 429:  # Rate limit -> tự động đổi sang key tiếp theo
                continue
            raise
    raise RuntimeError("Tất cả Groq keys đều hết hạn mức hoặc lỗi.")

if __name__ == "__main__":
    print(chat_groq("Chào bạn, trả lời trong 1 câu ngắn gọn."))`;
    }

    if (tab === "javascript") {
      if (mode === "encrypted") {
        return `// Chạy trực tiếp trên Node.js 20+, Deno, Bun hoặc trình duyệt (Web Crypto chuẩn)
const VAULT_URL = "${url}";
const PASSPHRASE = process.env.VAULT_PASSPHRASE; // Hoặc truyền trực tiếp vào hàm

export async function fetchGroqKeys(url = VAULT_URL, passphrase = PASSPHRASE) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(\`HTTP \${res.status}\`);
  const vault = await res.json();

  const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: b64ToBytes(vault.salt),
      iterations: vault.iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(vault.iv) },
    aesKey,
    b64ToBytes(vault.payload)
  );

  const items = JSON.parse(new TextDecoder().decode(decrypted));
  return items.filter((item) => item.active !== false).map((item) => item.value);
}`;
      }

      return `// Chạy trực tiếp trên Node.js 18+, Deno, Bun hoặc trình duyệt
const VAULT_URL = "${url}";

export async function fetchGroqKeys(url = VAULT_URL) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(\`HTTP \${res.status}\`);
  const data = await res.json();

  return (data.items || [])
    .filter((item) => item.active !== false)
    .map((item) => atob(item.value).split("").reverse().join(""));
}

export async function chatGroq(prompt, model = "llama-3.3-70b-versatile") {
  const keys = await fetchGroqKeys();
  const shuffled = [...keys].sort(() => Math.random() - 0.5);

  for (const apiKey of shuffled) {
    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: \`Bearer \${apiKey}\`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (res.status === 429) continue; // Tự xoay key khi gặp rate limit
    if (!res.ok) throw new Error(\`Groq HTTP \${res.status}\`);

    const data = await res.json();
    return data.choices[0].message.content;
  }

  throw new Error("Không còn Groq key khả dụng.");
}`;
    }

    if (tab === "curl") {
      if (mode === "encrypted") {
        return `# Chế độ Encrypted (AES-256-GCM) cần giải mã PBKDF2 + AES-GCM.
# Cách gọn nhất từ terminal là gọi Python/Node 1 lần rồi xuất ra biến môi trường:

export VAULT_PASSPHRASE="mat_khau_cua_ban"
GROQ_API_KEY=$(python3 -c '
import base64, json, os, urllib.request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
v = json.loads(urllib.request.urlopen("${url}").read())
k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=base64.b64decode(v["salt"]), iterations=v["iterations"]).derive(os.environ["VAULT_PASSPHRASE"].encode())
items = json.loads(AESGCM(k).decrypt(base64.b64decode(v["iv"]), base64.b64decode(v["payload"]), None))
print([i["value"] for i in items if i.get("active", True)][0])
')

curl -fsSL https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"`;
      }

      return `# Cách 1: Dùng curl + jq + base64 + rev (Linux / macOS / Git Bash)
GROQ_API_KEY=$(curl -fsSL "${url}" | jq -r '.items[] | select(.active != false) | .value' | head -n 1 | base64 -d | rev)

# Cách 2: Không có jq thì dùng Python chuẩn có sẵn
GROQ_API_KEY=$(curl -fsSL "${url}" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['items'][0]['value']).decode()[::-1])")

# Gọi API Groq bằng key vừa lấy
curl -fsSL https://api.groq.com/openai/v1/chat/completions \\
  -H "Authorization: Bearer $GROQ_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "llama-3.3-70b-versatile",
    "messages": [{"role": "user", "content": "Xin chào Groq!"}]
  }'`;
    }

    return "";
  }

  function renderCodeGuide() {
    const url = getActiveGuideUrl();

    if (state.guideTab === "deploy") {
      els.copyGuideCodeBtn.classList.add("hidden");
      els.codeGuideBody.innerHTML = `
        <div class="deploy-steps">
          <div class="deploy-step">
            <h3>Bước 1: Tạo Repository trên GitHub</h3>
            <p>
              Tạo repo mới trên GitHub (ví dụ: <code>groq-key-vault</code> hoặc đặt đúng tên <code>&lt;username&gt;.github.io</code> nếu muốn chạy ở domain gốc).
              Nếu dùng tài khoản GitHub Free, repo cần để Public để bật GitHub Pages miễn phí (khuyên dùng chế độ <strong>Encrypted AES-256-GCM</strong> trước khi push).
            </p>
          </div>
          <div class="deploy-step">
            <h3>Bước 2: Đẩy toàn bộ thư mục dự án lên GitHub</h3>
            <pre class="code-block">git init
git add .
git commit -m "Deploy Groq Key Vault"
git branch -M main
git remote add origin https://github.com/&lt;username&gt;/&lt;repo&gt;.git
git push -u origin main</pre>
          </div>
          <div class="deploy-step">
            <h3>Bước 3: Bật GitHub Pages (github.io)</h3>
            <p>
              Vào tab <strong>Settings → Pages</strong> trong repository → ở mục <strong>Build and deployment</strong>, chọn Source: <strong>Deploy from a branch</strong> → Branch: <strong>main</strong>, thư mục <strong>/ (root)</strong> → bấm <strong>Save</strong>.
            </p>
            <p>
              Sau 30–60 giây, web sẽ hoạt động tại <code>https://&lt;username&gt;.github.io/&lt;repo&gt;/</code> và file JSON sẽ nằm tại <code>https://&lt;username&gt;.github.io/&lt;repo&gt;/keys.json</code>.
            </p>
          </div>
        </div>
      `;
      return;
    }

    els.copyGuideCodeBtn.classList.remove("hidden");
    const snippet = getCodeSnippet(state.guideTab, state.guideMode, url);
    els.codeGuideBody.innerHTML = `<pre class="code-block"><code>${escapeHtml(snippet)}</code></pre>`;
  }

  function renderAll() {
    renderOverview();
    renderPickedStrip();
    renderKeyList();
    renderCodeGuide();
  }

  function pickKey(strategy) {
    const candidates = state.items.filter((k) => k.active && k.testStatus !== "invalid");
    if (candidates.length === 0) {
      showToast("Không có key nào đang hoạt động.");
      return;
    }
    let chosen;
    if (strategy === "random") {
      chosen = candidates[Math.floor(Math.random() * candidates.length)];
    } else {
      const prev = Number(localStorage.getItem(STORAGE_RR_KEY) || "0");
      const idx = prev % candidates.length;
      chosen = candidates[idx];
      localStorage.setItem(STORAGE_RR_KEY, String((idx + 1) % candidates.length));
    }

    state.pickedKey = chosen;
    state.pickedRevealed = false;
    renderPickedStrip();
    copyText(chosen.value, `Đã lấy & chép ${chosen.label}`);
  }

  async function testSingleKey(item) {
    item.testStatus = "testing";
    item.testDetail = "";
    renderKeyList();

    try {
      const res = await fetch(GROQ_MODELS_URL, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${item.value}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        const count = Array.isArray(data.data) ? data.data.length : 0;
        item.testStatus = "ok";
        item.testDetail = count ? `${count} models` : "OK";
      } else if (res.status === 401) {
        item.testStatus = "invalid";
        item.testDetail = "401";
      } else if (res.status === 429) {
        item.testStatus = "ratelimit";
        item.testDetail = "429";
      } else {
        item.testStatus = "error";
        item.testDetail = `HTTP ${res.status}`;
      }
    } catch {
      item.testStatus = "error";
      item.testDetail = "Lỗi mạng/CORS";
    }

    renderOverview();
    renderKeyList();
  }

  async function buildExportObject() {
    if (state.locked) {
      throw new Error("Vui lòng giải mã kho trước khi xuất keys.json.");
    }
    if (state.items.length === 0) {
      throw new Error("Danh sách key đang trống.");
    }

    if (state.exportMode === "encrypted") {
      const p1 = els.exportPassphrase.value;
      const p2 = els.exportPassphraseConfirm.value;
      if (p1.length < 6) {
        throw new Error("Master Passphrase phải có ít nhất 6 ký tự.");
      }
      if (p1 !== p2) {
        throw new Error("Hai lần nhập Passphrase không khớp.");
      }
      return encryptVaultItems(state.items, p1);
    }

    return {
      version: 1,
      provider: "groq",
      mode: "open",
      encoding: "rev-b64",
      updatedAt: new Date().toISOString(),
      items: state.items.map((item) => ({
        id: item.id,
        label: item.label,
        value: encodeRevB64(item.value),
        active: item.active,
      })),
    };
  }

  function bindEvents() {
    els.themeToggle.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme");
      applyTheme(cur === "dark" ? "light" : "dark");
    });

    els.reloadBtn.addEventListener("click", () => {
      loadVaultFromRepo();
      showToast("Đã tải lại dữ liệu từ repo.");
    });

    els.copyEndpointBtn.addEventListener("click", () => {
      copyText(els.endpointPreview.value, "Đã chép Endpoint URL.");
    });

    els.pickRoundRobinBtn.addEventListener("click", () => pickKey("round-robin"));
    els.pickRandomBtn.addEventListener("click", () => pickKey("random"));

    els.testAllBtn.addEventListener("click", async () => {
      els.testAllBtn.disabled = true;
      for (const item of state.items) {
        if (item.active) {
          await testSingleKey(item);
        }
      }
      els.testAllBtn.disabled = false;
      showToast("Đã hoàn tất kiểm tra tất cả key.");
    });

    els.copyEnvBtn.addEventListener("click", () => {
      const lines = state.items
        .map((item, i) => `GROQ_API_KEY_${i + 1}=${item.value}`)
        .join("\n");
      copyText(lines, "Đã chép tất cả key dạng .env.");
    });

    els.copyJsonBtn.addEventListener("click", () => {
      const arr = state.items.filter((i) => i.active).map((i) => i.value);
      if (arr.length === 0) {
        showToast("Không có key nào đang bật để sao chép.");
        return;
      }
      copyText(JSON.stringify(arr, null, 2), "Đã chép mảng JSON các key hoạt động.");
    });

    els.pickedToggleBtn.addEventListener("click", () => {
      state.pickedRevealed = !state.pickedRevealed;
      renderPickedStrip();
    });

    els.pickedCopyBtn.addEventListener("click", () => {
      if (state.pickedKey) {
        copyText(state.pickedKey.value, `Đã chép ${state.pickedKey.label}`);
      }
    });

    els.unlockToggleVis.addEventListener("click", () => {
      const isPwd = els.unlockPassphrase.type === "password";
      els.unlockPassphrase.type = isPwd ? "text" : "password";
      els.unlockToggleVis.textContent = isPwd ? "Ẩn" : "Hiện";
    });

    els.unlockForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      els.unlockError.classList.add("hidden");
      const pass = els.unlockPassphrase.value;
      if (!pass) return;

      try {
        const items = await decryptVaultPayload(state.rawVault, pass);
        state.locked = false;
        state.items = normalizeDecodedItems(items, "plain");
        els.unlockPassphrase.value = "";
        renderAll();
        showToast("Giải mã kho thành công.");
      } catch {
        els.unlockError.textContent = "Passphrase không đúng hoặc dữ liệu mã hóa bị sai định dạng.";
        els.unlockError.classList.remove("hidden");
      }
    });

    els.toggleAllVisibilityBtn.addEventListener("click", () => {
      state.revealAll = !state.revealAll;
      renderKeyList();
    });

    els.searchInput.addEventListener("input", (e) => {
      state.search = e.target.value;
      renderKeyList();
    });

    document.querySelectorAll("[data-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.filter = btn.dataset.filter;
        document.querySelectorAll("[data-filter]").forEach((b) => {
          b.classList.toggle("is-active", b === btn);
        });
        renderKeyList();
      });
    });

    els.keyList.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-action]");
      if (!btn) return;
      const card = btn.closest(".key-card");
      if (!card) return;
      const item = state.items.find((i) => i.id === card.dataset.id);
      if (!item) return;

      const action = btn.dataset.action;
      if (action === "toggle-vis") {
        item.revealed = !item.revealed;
        renderKeyList();
      } else if (action === "copy") {
        copyText(item.value, `Đã chép ${item.label}`);
      } else if (action === "test") {
        testSingleKey(item);
      } else if (action === "toggle-active") {
        item.active = !item.active;
        renderOverview();
        renderKeyList();
      } else if (action === "delete") {
        state.items = state.items.filter((i) => i.id !== item.id);
        renderOverview();
        renderKeyList();
        showToast(`Đã xóa ${item.label} khỏi danh sách phiên hiện tại.`);
      }
    });

    els.keyList.addEventListener("input", (e) => {
      if (e.target.dataset.action !== "rename") return;
      const card = e.target.closest(".key-card");
      if (!card) return;
      const item = state.items.find((i) => i.id === card.dataset.id);
      if (item) {
        item.label = e.target.value;
      }
    });

    document.querySelectorAll("[data-guide-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.guideMode = btn.dataset.guideMode;
        syncSegmentedActive("[data-guide-mode]", "guideMode", state.guideMode);
        renderCodeGuide();
      });
    });

    document.querySelectorAll("[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.guideTab = btn.dataset.tab;
        document.querySelectorAll("[data-tab]").forEach((b) => {
          b.classList.toggle("is-active", b === btn);
        });
        renderCodeGuide();
      });
    });

    els.guideUrlInput.addEventListener("input", () => {
      state.customGuideUrl = els.guideUrlInput.value;
      renderCodeGuide();
    });

    els.guideUrlReset.addEventListener("click", () => {
      state.customGuideUrl = "";
      els.guideUrlInput.value = resolveEndpointUrl();
      renderCodeGuide();
    });

    els.copyGuideCodeBtn.addEventListener("click", () => {
      const code = getCodeSnippet(state.guideTab, state.guideMode, getActiveGuideUrl());
      copyText(code, "Đã chép đoạn code mẫu.");
    });

    els.addKeyForm.addEventListener("submit", (e) => {
      e.preventDefault();
      setManageFeedback("");
      if (state.locked) {
        setManageFeedback("Hãy giải mã kho trước khi thêm key mới.");
        return;
      }
      const raw = els.newKeyInput.value.trim();
      const label = els.newKeyLabel.value.trim() || `Groq Key #${String(state.items.length + 1).padStart(2, "0")}`;
      if (!raw.startsWith("gsk_") || raw.length < 24) {
        setManageFeedback("Key không hợp lệ (Groq key phải bắt đầu bằng gsk_ và đủ độ dài).");
        return;
      }
      if (state.items.some((i) => i.value === raw)) {
        setManageFeedback("Key này đã tồn tại trong danh sách.");
        return;
      }

      state.items.push({
        id: `key-${Date.now().toString(36)}`,
        label,
        value: raw,
        active: true,
        revealed: false,
        testStatus: "untested",
        testDetail: "",
      });
      els.newKeyInput.value = "";
      els.newKeyLabel.value = "";
      renderOverview();
      renderKeyList();
      setManageFeedback("Đã thêm key vào phiên làm việc. Hãy tải keys.json mới để cập nhật lên GitHub.");
    });

    document.querySelectorAll("[data-export-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.exportMode = btn.dataset.exportMode;
        syncSegmentedActive("[data-export-mode]", "exportMode", state.exportMode);
        els.exportPassphraseRow.classList.toggle("hidden", state.exportMode !== "encrypted");
      });
    });

    els.downloadJsonBtn.addEventListener("click", async () => {
      setManageFeedback("");
      try {
        const obj = await buildExportObject();
        const text = JSON.stringify(obj, null, 2) + "\n";
        const blob = new Blob([text], { type: "application/json;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "keys.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setManageFeedback(
          state.exportMode === "encrypted"
            ? "Đã tải xuống keys.json đã mã hóa AES-256-GCM. Hãy thay thế keys.json và xóa/cập nhật keys-fallback.js trước khi push lên GitHub."
            : "Đã tải xuống keys.json. Hãy thay thế tệp keys.json trong repository GitHub và push lại."
        );
      } catch (err) {
        setManageFeedback(err.message);
      }
    });

    els.copyExportJsonBtn.addEventListener("click", async () => {
      setManageFeedback("");
      try {
        const obj = await buildExportObject();
        const text = JSON.stringify(obj, null, 2) + "\n";
        await copyText(text, "Đã chép toàn bộ nội dung keys.json.");
        setManageFeedback(
          state.exportMode === "encrypted"
            ? "Đã chép JSON đã mã hóa AES-256-GCM. Dán đè vào keys.json và nhớ xóa keys-fallback.js nếu repo công khai."
            : "Đã chép nội dung JSON. Dán đè vào tệp keys.json trên GitHub."
        );
      } catch (err) {
        setManageFeedback(err.message);
      }
    });

    els.importJsonInput.addEventListener("change", async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        loadVaultObject(parsed, `Đang xem dữ liệu nạp thủ công từ tệp "${file.name}".`);
        setManageFeedback(`Đã nạp thành công từ "${file.name}".`);
      } catch (err) {
        setManageFeedback(`Tệp JSON không hợp lệ: ${err.message}`);
      } finally {
        e.target.value = "";
      }
    });

    els.resetSessionBtn.addEventListener("click", () => {
      setManageFeedback("");
      loadVaultFromRepo();
      showToast("Đã khôi phục danh sách theo repo.");
    });
  }

  initTheme();
  bindEvents();
  loadVaultFromRepo();
})();
