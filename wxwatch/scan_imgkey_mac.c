/* 在微信进程的可读写内存里找能解开 V2 图片的 ASCII 密钥。需要 root，且 SIP 已关闭。 */
#include <CommonCrypto/CommonCryptor.h>
#include <ctype.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int looks_like_image(const unsigned char *pt) {
    /* 只认完整文件头。单凭 FF D8 会把大量无关字符串误当成图片密钥。 */
    if (memcmp(pt, "\x89PNG\r\n\x1a\n", 8) == 0) return 1;
    if (memcmp(pt, "GIF87a", 6) == 0 || memcmp(pt, "GIF89a", 6) == 0) return 1;
    if (memcmp(pt, "wxgf", 4) == 0) return 1;
    if (pt[0] == 0xff && pt[1] == 0xd8 && pt[2] == 0xff && (pt[3] == 0xe0 || pt[3] == 0xe1 || pt[3] == 0xdb || pt[3] == 0xc0 || pt[3] == 0xc4)) return 1;
    return 0;
}

static int try_key(const unsigned char *key, size_t key_len, const unsigned char *ct, size_t ct_len) {
    unsigned char out[16];
    size_t moved = 0;
    if (ct_len < 16 || (key_len != 16 && key_len != 24 && key_len != 32)) return 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode,
                                     key, key_len, NULL, ct, 16, out, sizeof out, &moved);
    return status == kCCSuccess && looks_like_image(out);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: scan_imgkey_mac pid ciphertext_hex\n");
        return 2;
    }
    int pid = atoi(argv[1]);
    const char *hex = argv[2];
    size_t hex_len = strlen(hex);
    if (hex_len < 32 || hex_len % 2) return 2;
    size_t ct_len = hex_len / 2;
    unsigned char *ct = malloc(ct_len);
    if (!ct) return 1;
    for (size_t i = 0; i < ct_len; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return 2;
        ct[i] = (unsigned char)byte;
    }
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %d\n", kr);
        return 1;
    }
    mach_vm_address_t address = 0;
    int printed = 0;
    while (printed < 30) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kr = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &count, &object);
        if (kr != KERN_SUCCESS) break;
        int readable = (info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE);
        if (readable && size > 0 && size <= 64 * 1024 * 1024) {
            unsigned char *buffer = malloc((size_t)size);
            if (buffer) {
                mach_vm_size_t out = 0;
                kr = mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)buffer, &out);
                if (kr == KERN_SUCCESS && out > 32) {
                    size_t i = 0;
                    size_t n = (size_t)out;
                    while (i < n && printed < 30) {
                        if (!isalnum(buffer[i])) {
                            i++;
                            continue;
                        }
                        size_t j = i;
                        while (j < n && isalnum(buffer[j]) && j - i < 64) j++;
                        size_t len = j - i;
                        int bounded = (j == n || !isalnum(buffer[j]));
                        if (bounded && (len == 16 || len == 32)) {
                            size_t use = len;
                            if (try_key(buffer + i, len, ct, ct_len)) use = len;
                            else if (len == 32 && try_key(buffer + i, 16, ct, ct_len)) use = 16;
                            else use = 0;
                            if (use) {
                                fwrite(buffer + i, 1, use, stdout);
                                fputc('\n', stdout);
                                fflush(stdout);
                                printed++;
                            }
                        }
                        i = j > i ? j : i + 1;
                    }
                }
                free(buffer);
            }
        }
        address += size;
        if (address == 0) break;
    }
    return printed ? 0 : 3;
}
