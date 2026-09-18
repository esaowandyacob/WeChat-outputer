"use strict";

// Frida 探针：对 sqlite3_key / sqlite3_key_v2 / WCDB setCipherKey 下断并回传参数。
// 由 windows_key_hook.py 注入，不单独运行。

function toHex(ptr, length) {
  if (ptr === null || ptr.isNull() || length <= 0) {
    return "";
  }
  const size = Math.min(Math.max(length, 1), 128);
  try {
    const bytes = ptr.readByteArray(size);
    if (bytes === null) {
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
  if (ptr === null || ptr.isNull()) {
    return "";
  }
  try {
    return ptr.readUtf8String() || "";
  } catch (error) {
    return "";
  }
}

function dumpRegs(context) {
  const names = ["rcx", "rdx", "r8", "r9"];
  const out = {};
  names.forEach(function (name) {
    try {
      const value = context[name];
      out[name] = value.toString();
      out[name + "_hex32"] = toHex(value, 32);
      out[name + "_i32"] = value.toInt32();
    } catch (error) {
      out[name] = "";
    }
  });
  return out;
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
      let dbName = "";
      let pKey = args[1];
      let nKey = 0;
      if (variant === "v2") {
        dbName = readUtf8(args[1]);
        pKey = args[2];
        try {
          nKey = args[3].toInt32();
        } catch (error) {
          nKey = 0;
        }
      } else if (variant === "cipher") {
        pKey = args[1];
        try {
          nKey = args[2].toInt32();
          if (nKey === 0) {
            nKey = Number(args[2]);
          }
        } catch (error) {
          nKey = 32;
        }
      } else {
        try {
          nKey = args[2].toInt32();
        } catch (error) {
          nKey = 0;
        }
      }
      const readLen = nKey > 0 && nKey <= 128 ? nKey : 64;
      send({
        type: "call",
        name: name,
        variant: variant,
        nKey: nKey,
        dbName: dbName,
        hex: toHex(pKey, readLen),
        extra32: toHex(pKey, 32),
        extra64: toHex(pKey, 64),
        regs: dumpRegs(this.context),
      });
    },
  });
}

function tryExport(moduleName, exportName, variant) {
  try {
    const address = Module.findExportByName(moduleName, exportName);
    if (address !== null) {
      hookAddress((moduleName || "*") + "!" + exportName, address, variant);
      return true;
    }
  } catch (error) {}
  return false;
}

function hookModule(module) {
  const interesting = /key|cipher|codec|wcdb|sqlcipher|sqlite3/i;
  let exports = [];
  try {
    exports = module.enumerateExports();
  } catch (error) {
    exports = [];
  }
  send({ type: "module", name: module.name, base: module.base.toString(), size: module.size, exports: exports.length });
  exports.forEach(function (item) {
    if (!interesting.test(item.name)) {
      return;
    }
    let variant = "key";
    if (/key_v2/i.test(item.name)) {
      variant = "v2";
    } else if (/CipherKey|setCipher|set_cipher|codec_ctx_set/i.test(item.name)) {
      variant = "cipher";
    } else if (!/key|rekey/i.test(item.name)) {
      return;
    }
    hookAddress(module.name + "!" + item.name, item.address, variant);
  });
  try {
    module.enumerateSymbols().forEach(function (item) {
      if (!item.address || !interesting.test(item.name)) {
        return;
      }
      if (/sqlite3_key_v2/.test(item.name)) {
        hookAddress(module.name + "!" + item.name, item.address, "v2");
      } else if (/sqlite3_key$/.test(item.name) || /sqlite3_rekey$/.test(item.name)) {
        hookAddress(module.name + "!" + item.name, item.address, "key");
      } else if (/setCipherKey|sqlcipher_codec_ctx_set/.test(item.name)) {
        hookAddress(module.name + "!" + item.name, item.address, "cipher");
      }
    });
  } catch (error) {}
}

const mangled = [
  "?setCipherKey@Database@WCDB@@QEAA_NPEBX_K@Z",
  "?setCipherKey@Handle@WCDB@@QEAA_NPEBX_K@Z",
  "?setCipherKey@CipherConfig@WCDB@@QEAAXPEBX_K@Z",
  "?setCipherKey@HandleParam@WCDB@@QEAAXAEBVUnsafeStringView@2@@Z",
  "sqlite3_key",
  "sqlite3_key_v2",
  "sqlite3_rekey",
  "sqlite3_rekey_v2",
  "sqlcipher_codec_ctx_set_pass",
  "sqlcipher_codec_ctx_set_kdf",
];

mangled.forEach(function (name) {
  tryExport(null, name, /v2/.test(name) ? "v2" : /Cipher|codec/.test(name) ? "cipher" : "key");
  try {
    const address = DebugSymbol.fromName(name);
    if (address && !address.isNull()) {
      hookAddress("sym!" + name, address, /v2/.test(name) ? "v2" : /Cipher|codec/.test(name) ? "cipher" : "key");
    }
  } catch (error) {}
});

Process.enumerateModules().forEach(hookModule);

send({ type: "ready", hooked: Object.keys(hooked).length });
