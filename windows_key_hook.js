"use strict";

// 只钩 sqlite3_key / rekey / WCDB setCipherKey，避免匹配到 CryptImportKey、sqlite3_keyword。

function toHex(ptr, length) {
  if (!ptr || ptr.isNull() || length <= 0) {
    return "";
  }
  const size = Math.min(Math.max(length, 1), 128);
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

function readUtf8(ptr) {
  if (!ptr || ptr.isNull()) {
    return "";
  }
  try {
    return ptr.readUtf8String() || "";
  } catch (error) {
    return "";
  }
}

function classify(name) {
  if (/sqlite3_key_v2/i.test(name) || /sqlite3_rekey_v2/i.test(name)) {
    return "v2";
  }
  if (/sqlite3_key$/i.test(name) || /sqlite3_rekey$/i.test(name)) {
    return "key";
  }
  if (/setCipherKey/i.test(name) || /sqlcipher_codec_ctx_set/i.test(name)) {
    return "cipher";
  }
  return "";
}

const hooked = {};
let callCount = 0;

function hookAddress(name, address, variant) {
  const key = address.toString();
  if (hooked[key]) {
    return;
  }
  hooked[key] = name;
  send({ type: "hook", name: name, variant: variant, address: key });
  Interceptor.attach(address, {
    onEnter: function (args) {
      callCount += 1;
      if (callCount > 200) {
        return;
      }
      let dbName = "";
      let pKey = ptr(0);
      let nKey = 0;
      try {
        if (variant === "v2") {
          dbName = readUtf8(args[1]);
          pKey = args[2];
          nKey = parseInt(String(args[3])) || 0;
        } else if (variant === "cipher") {
          pKey = args[1];
          nKey = parseInt(String(args[2])) || 0;
        } else {
          pKey = args[1];
          nKey = parseInt(String(args[2])) || 0;
        }
      } catch (error) {
        nKey = 32;
      }
      if (nKey < 0 || nKey > 128) {
        nKey = 32;
      }
      send({
        type: "call",
        name: name,
        variant: variant,
        nKey: nKey,
        dbName: dbName,
        hex: toHex(pKey, nKey || 32),
        extra32: toHex(pKey, 32),
      });
    },
  });
}

function tryExport(moduleName, exportName, variant) {
  try {
    const address = Module.findExportByName(moduleName, exportName);
    if (address) {
      hookAddress((moduleName || "*") + "!" + exportName, address, variant);
    }
  } catch (error) {}
}

const allow = [
  "sqlite3_key",
  "sqlite3_key_v2",
  "sqlite3_rekey",
  "sqlite3_rekey_v2",
  "sqlcipher_codec_ctx_set_pass",
  "sqlcipher_codec_ctx_set_kdf",
  "?setCipherKey@Database@WCDB@@QEAA_NPEBX_K@Z",
  "?setCipherKey@Handle@WCDB@@QEAA_NPEBX_K@Z",
  "?setCipherKey@CipherConfig@WCDB@@QEAAXPEBX_K@Z",
];

allow.forEach(function (name) {
  const variant = /v2/.test(name) ? "v2" : /Cipher|codec/.test(name) ? "cipher" : "key";
  tryExport(null, name, variant);
});

Process.enumerateModules().forEach(function (module) {
  send({ type: "module", name: module.name, base: module.base.toString(), size: module.size });
  let exports = [];
  try {
    exports = module.enumerateExports();
  } catch (error) {
    return;
  }
  send({ type: "module", name: module.name, exports: exports.length });
  exports.forEach(function (item) {
    const variant = classify(item.name);
    if (variant) {
      hookAddress(module.name + "!" + item.name, item.address, variant);
    }
  });
});

send({ type: "ready", hooked: Object.keys(hooked).length });
