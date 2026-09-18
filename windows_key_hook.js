"use strict";

// 仅在 --frida 时使用。默认请用硬件断点方案，避免注入 frida-agent.dll 导致微信崩溃。

function toHex(ptr, length) {
  if (!ptr || ptr.isNull() || length <= 0) {
    return "";
  }
  const size = Math.min(Math.max(length, 1), 64);
  try {
    const bytes = ptr.readByteArray(size);
    if (!bytes) {
      return "";
    }
    return Array.from(new Uint8Array(bytes))
      .map(function (value) {
        return ("0" + value.toString(16)).slice(-2);
      })
      .join("");
  } catch (error) {
    return "";
  }
}

function classify(name) {
  if (name === "sqlite3_key_v2" || name === "sqlite3_rekey_v2") {
    return "v2";
  }
  if (name === "sqlite3_key" || name === "sqlite3_rekey") {
    return "key";
  }
  if (/setCipherKey/i.test(name)) {
    return "cipher";
  }
  return "";
}

const hooked = {};

function hookAddress(name, address, variant) {
  const key = address.toString();
  if (hooked[key]) {
    return;
  }
  hooked[key] = name;
  send({ type: "hook", name: name, variant: variant, address: key });
  Interceptor.attach(address, {
    onEnter: function (args) {
      let pKey = args[1];
      let nKey = 32;
      try {
        if (variant === "v2") {
          pKey = args[2];
          nKey = parseInt(String(args[3]), 16) || parseInt(String(args[3]), 10) || 32;
        } else {
          nKey = parseInt(String(args[2]), 16) || parseInt(String(args[2]), 10) || 32;
        }
      } catch (error) {}
      if (nKey < 8 || nKey > 64) {
        nKey = 32;
      }
      send({
        type: "call",
        name: name,
        variant: variant,
        nKey: nKey,
        hex: toHex(pKey, nKey),
        extra32: toHex(pKey, 32),
      });
    },
  });
}

["Weixin.dll", "Weixin.exe"].forEach(function (name) {
  const module = Process.findModuleByName(name);
  if (!module) {
    send({ type: "module", name: name, missing: true });
    return;
  }
  send({ type: "module", name: module.name, base: module.base.toString(), size: module.size });
  try {
    module.enumerateExports().forEach(function (item) {
      const variant = classify(item.name);
      if (variant) {
        hookAddress(module.name + "!" + item.name, item.address, variant);
      }
    });
  } catch (error) {
    send({ type: "error_info", name: name, message: String(error) });
  }
});

send({ type: "ready", hooked: Object.keys(hooked).length });
