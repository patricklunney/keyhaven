// Keyhaven browser client: drives the WebAuthn ceremonies against the JSON API.
"use strict";

const b64u = {
  decode(s) {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  },
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

function creationOptionsFromJSON(pk) {
  if (window.PublicKeyCredential?.parseCreationOptionsFromJSON) {
    return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
  }
  return {
    ...pk,
    challenge: b64u.decode(pk.challenge),
    user: { ...pk.user, id: b64u.decode(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.decode(c.id) })),
  };
}

function requestOptionsFromJSON(pk) {
  if (window.PublicKeyCredential?.parseRequestOptionsFromJSON) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
  }
  return {
    ...pk,
    challenge: b64u.decode(pk.challenge),
    allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.decode(c.id) })),
  };
}

function credentialToJSON(cred) {
  if (typeof cred.toJSON === "function") {
    try { return cred.toJSON(); } catch (_) { /* fall through */ }
  }
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: { clientDataJSON: b64u.encode(r.clientDataJSON) },
  };
  if (r.attestationObject) {
    out.response.attestationObject = b64u.encode(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    out.response.authenticatorData = b64u.encode(r.authenticatorData);
    out.response.signature = b64u.encode(r.signature);
    if (r.userHandle) out.response.userHandle = b64u.encode(r.userHandle);
  }
  return out;
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function friendly(err) {
  if (err?.name === "NotAllowedError") return "The request was cancelled or timed out.";
  if (err?.name === "InvalidStateError") return "This device already has a passkey for this account.";
  if (err?.name === "SecurityError") return "Passkeys aren't available on this address.";
  return err?.message || "Something went wrong.";
}

function setStatus(text, isError) {
  const el = document.getElementById("status");
  if (!el) return;
  el.textContent = text;
  el.classList.toggle("error", !!isError);
}

function supported() {
  if (!window.PublicKeyCredential) {
    setStatus("This browser doesn't support passkeys.", true);
    return false;
  }
  return true;
}

async function register(body, name) {
  const opts = await postJSON("/webauthn/register/begin", body);
  const cred = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(opts.publicKey) });
  const q = name ? `?name=${encodeURIComponent(name)}` : "";
  await postJSON(`/webauthn/register/finish${q}`, credentialToJSON(cred));
}

async function login() {
  const opts = await postJSON("/webauthn/login/begin");
  const cred = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(opts.publicKey) });
  await postJSON("/webauthn/login/finish", credentialToJSON(cred));
}

function guessDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android device";
  if (/Mac OS X/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows PC";
  if (/Linux/.test(ua)) return "Linux device";
  return "Passkey";
}

document.addEventListener("DOMContentLoaded", () => {
  const loginEl = document.getElementById("login");
  if (loginEl) {
    const btn = document.getElementById("login-btn");
    btn.addEventListener("click", async () => {
      if (!supported()) return;
      btn.disabled = true;
      setStatus("Waiting for your passkey…");
      try {
        await login();
        setStatus("Signed in. Redirecting…");
        window.location.assign(loginEl.dataset.next);
      } catch (e) {
        setStatus(friendly(e), true);
        btn.disabled = false;
      }
    });
  }

  const regEl = document.getElementById("register");
  if (regEl) {
    regEl.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (!supported()) return;
      const username = regEl.username.value.trim();
      if (!regEl.username.checkValidity()) {
        setStatus("Username must be 3–64 characters: letters, numbers and . _ @ + -", true);
        return;
      }
      const btn = regEl.querySelector("button");
      btn.disabled = true;
      setStatus("Follow the prompt to create your passkey…");
      try {
        await register({ username, displayName: regEl.displayName.value.trim() }, guessDeviceName());
        setStatus("Account created. Redirecting…");
        window.location.assign(regEl.dataset.next);
      } catch (e) {
        setStatus(friendly(e), true);
        btn.disabled = false;
      }
    });
  }

  const addEl = document.getElementById("add-passkey");
  if (addEl) {
    const btn = document.getElementById("add-btn");
    btn.addEventListener("click", async () => {
      if (!supported()) return;
      btn.disabled = true;
      setStatus("Follow the prompt to create your passkey…");
      try {
        const name = document.getElementById("passkey-name").value.trim() || guessDeviceName();
        await register({}, name);
        window.location.reload();
      } catch (e) {
        setStatus(friendly(e), true);
        btn.disabled = false;
      }
    });
  }
});
