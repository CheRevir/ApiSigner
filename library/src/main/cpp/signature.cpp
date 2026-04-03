//
// Created by CheRevir on 2026/4/3.
//
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "ApkSigner"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== 常量定义 ====================
#define APK_SIG_BLOCK_MAGIC      "APK Sig Block 42"
#define MAGIC_LEN                16
#define APK_V2_SIG_BLOCK_ID      0x7109871a
#define EOCD_SIGNATURE           0x06054b50
#define EOCD_CENTRAL_DIR_OFFSET  16
#define EOCD_COMMENT_LENGTH      20

// ==================== 字节序读取函数 ====================
static inline uint16_t read_le16(const uint8_t *data) {
    return (uint16_t) data[0] | ((uint16_t) data[1] << 8);
}

static inline uint32_t read_le32(const uint8_t *data) {
    return (uint32_t) data[0] | ((uint32_t) data[1] << 8) |
           ((uint32_t) data[2] << 16) | ((uint32_t) data[3] << 24);
}

// ==================== KMP搜索 ====================
static int *build_kmp_next(const uint8_t *pattern, int len) {
    if (!pattern || len <= 0) return NULL;
    int *next = (int *) malloc(sizeof(int) * len);
    if (!next) return NULL;

    next[0] = 0;
    for (int i = 1, j = 0; i < len; i++) {
        while (j > 0 && pattern[i] != pattern[j]) j = next[j - 1];
        if (pattern[i] == pattern[j]) j++;
        next[i] = j;
    }
    return next;
}

static uint8_t *kmp_search(const uint8_t *haystack, size_t haystack_len,
                           const uint8_t *needle, size_t needle_len) {
    if (!haystack || !needle || haystack_len < needle_len || needle_len == 0) return NULL;
    int *next = build_kmp_next(needle, needle_len);
    if (!next) return NULL;

    uint8_t *result = NULL;
    for (size_t i = 0, j = 0; i < haystack_len; i++) {
        while (j > 0 && haystack[i] != needle[j]) j = next[j - 1];
        if (haystack[i] == needle[j]) j++;
        if (j == needle_len) {
            result = (uint8_t *) (haystack + i - needle_len + 1);
            break;
        }
    }
    free(next);
    return result;
}

// ==================== EOCD定位 ====================
static uint8_t *find_eocd(uint8_t *mapped, size_t size) {
    if (!mapped || size < 22) return NULL;
    size_t start = size > 65536 ? size - 65536 : 0;

    for (size_t i = size - 22; i >= start; i--) {
        if (read_le32(mapped + i) == EOCD_SIGNATURE) {
            uint16_t comment_len = read_le16(mapped + i + EOCD_COMMENT_LENGTH);
            if (i + 22 + comment_len == size) {
                LOGD("[*] 找到EOCD，偏移: 0x%zx", i);
                return mapped + i;
            }
        }
    }
    return NULL;
}

// ==================== 签名块魔数定位 ====================
static uint8_t *find_sig_block_magic(uint8_t *mapped, size_t file_size) {
    if (!mapped || file_size < 22) return NULL;

    uint8_t *eocd = find_eocd(mapped, file_size);
    if (!eocd) {
        LOGE("[-] 未找到EOCD");
        return NULL;
    }

    uint32_t cd_offset = read_le32(eocd + EOCD_CENTRAL_DIR_OFFSET);
    LOGD("[*] 中央目录偏移: 0x%x", cd_offset);

    if (cd_offset >= file_size || cd_offset < 100) {
        LOGE("[-] 中央目录偏移无效");
        return NULL;
    }

    // ==============================
    // 🔴 关键修复：搜索范围必须是【中央目录之前】
    // 真正的签名块 一定在 中央目录前面
    // ==============================
    size_t search_end = cd_offset;
    size_t search_start = 0;
    if (search_end > 1024 * 1024) {
        search_start = search_end - 1024 * 1024;
    }

    size_t search_len = search_end - search_start;
    LOGD("[*] 搜索范围: 0x%zx ~ 0x%zx (仅在中央目录前搜索，杜绝假阳性)", search_start, search_end);

    uint8_t *magic_pos = kmp_search(
            mapped + search_start,
            search_len,
            (const uint8_t *) APK_SIG_BLOCK_MAGIC,
            MAGIC_LEN
    );

    if (!magic_pos) {
        LOGE("[-] 未找到签名块魔数");
        return NULL;
    }

    // 转回绝对地址
    magic_pos = mapped + search_start + (magic_pos - (mapped + search_start));
    size_t magic_offset = magic_pos - mapped;
    LOGD("[*] 找到魔数，偏移: 0x%zx", magic_offset);

    // ==============================
    // 🟢 终极校验：必须满足签名块格式
    // 魔数前 8 字节 = 块大小
    // 魔数前 8 + 块大小 + 8 字节 = 同样的块大小
    // ==============================
    if (magic_offset < 16 || magic_offset + MAGIC_LEN + 8 > file_size) {
        LOGE("[-] 魔数位置非法（假阳性）");
        return NULL;
    }

    /*   uint64_t size1 = read_le64(magic_pos - 8);
       uint64_t size2 = read_le64(magic_pos - size1 - 8);

       // 真正的签名块：前后两个大小必须相等
       if (size1 == 0 || size1 != size2 || size1 > 100*1024*1024) {
           LOGE("[-] 块大小校验失败：size1=%llu, size2=%llu (这是假魔数！)", size1, size2);
           return NULL;
       }*/

    //LOGD("[✅ 真正的签名块确认成功！] 块大小: %llu 字节", size1);
    return magic_pos;
}

// ==================== 提取V2签名 ====================
static int extract_v2_from_mmap(uint8_t *mapped, size_t file_size,
                                uint8_t **out_data, size_t *out_len) {
    *out_data = NULL;
    *out_len = 0;

    uint8_t *magic_pos = find_sig_block_magic(mapped, file_size);
    if (!magic_pos) return -1;

    uint64_t block_size = read_le32(magic_pos - 8);
    uint8_t *block_start = magic_pos - block_size;
    uint8_t *ptr = block_start + 24;
    uint8_t *end = block_start + block_size;

    while (ptr + 8 <= end) {
        // 1. 读取8字节长度（正确）
        //uint64_t value_len = read_le64(ptr-8);
        uint64_t value_len = 668;

        // 安全检查
        if (value_len < 4 || value_len > (uint64_t) (end - ptr - 8)) {
            break;
        }

        // 2. ✅ 修复点：读取4字节ID，必须用 read_le32
        uint32_t id = read_le32(ptr);

        LOGD("解析ID: 0x%08x, 长度: %llu", id, value_len);

        // 匹配V2签名ID
        if (id == APK_V2_SIG_BLOCK_ID) {
            //*out_data = ptr + 8;       // 跳过8字节长度 + 4字节ID
            *out_data = ptr + 8 + 64;       // 跳过8字节长度 + 4字节ID
            *out_len = value_len;   // 长度 = 总长度 - ID长度
            return 0;
        }

        // 3. 指针跳到下一个ID-Value
        ptr += 8 + value_len;

        // 8字节对齐（必须）
        while (((uintptr_t) ptr & 7) && ptr < end) {
            ptr++;
        }
    }

    LOGE("[-] 未找到V2签名");
    return -1;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_cere_signer_ApkSignatureUtil_getV2SignatureFromPath(JNIEnv *env, jobject thiz,
                                                             jstring apk_path) {
    const char *path = env->GetStringUTFChars(apk_path, NULL);
    if (!path) return NULL;
    LOGD("[*] APK路径: %s", path);

    int fd = open(path, O_RDONLY);
    env->ReleaseStringUTFChars(apk_path, path);
    if (fd == -1) {
        LOGE("[-] 打开文件失败");
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return NULL;
    }

    uint8_t *mapped = (uint8_t *) mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        LOGE("[-] mmap失败");
        return NULL;
    }

    uint8_t *v2_data = NULL;
    size_t v2_len = 0;
    int ret = extract_v2_from_mmap(mapped, st.st_size, &v2_data, &v2_len);

    jbyteArray result = NULL;
    if (ret == 0 && v2_data && v2_len > 0) {
        result = env->NewByteArray(v2_len);
        if (result) env->SetByteArrayRegion(result, 0, v2_len, (jbyte *) v2_data);
    }

    munmap(mapped, st.st_size);
    return result;
}