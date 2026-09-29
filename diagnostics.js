export function detectEnvironment() {
  const ua = navigator.userAgent || "";
  const text = `${ua} ${navigator.platform || ""}`;

  const firmwareMatch =
    text.match(/(?:FW|Firmware|PlayStation 4)[\/\s:_-]*(\d+\.\d+)/i);

  const firmware = firmwareMatch ? firmwareMatch[1] : null;

  return {
    userAgent: ua,
    platform: navigator.platform || "unknown",
    firmware,
    isPS4: /PlayStation 4|PS4/i.test(text),
    webkit: /AppleWebKit/i.test(ua),
    secureContext: window.isSecureContext === true,
    indexedDB: "indexedDB" in window,
    localStorage: "localStorage" in window
  };
}

export function targetCheck(env) {
  return {
    exact: env.firmware === "14.00",
    firmware: env.firmware || "unknown"
  };
}

export async function storageCheck() {
  try {
    const key = "__zoof13r_test__";
    localStorage.setItem(key, "1");
    const ok = localStorage.getItem(key) === "1";
    localStorage.removeItem(key);
    return ok;
  } catch {
    return false;
  }
}
