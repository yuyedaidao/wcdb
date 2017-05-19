#include "crypto.hpp"
#include <alloca.h>
#include <sqlite3.h>

// Forward declearations from SQLCipher
enum {
    CIPHER_DECRYPT = 0,
};

enum {
    CIPHER_READ_CTX = 0,
    CIPHER_READWRITE_CTX = 2,
};

typedef struct Db Db;

extern "C" {
    /* activation and initialization */
    void sqlcipher_activate();
    void sqlcipher_deactivate();
    int sqlcipher_codec_ctx_init(codec_ctx **, void *, void *, void *, const void *, int);
    void sqlcipher_codec_ctx_free(codec_ctx **);
    int sqlcipher_codec_key_derive(codec_ctx *);
    int sqlcipher_codec_key_copy(codec_ctx *, int);

    /* page cipher implementation */
    int sqlcipher_page_cipher(codec_ctx *, int, int, int, int, unsigned char *, unsigned char *);

    /* context setters & getters */
    //void sqlcipher_codec_ctx_set_error(codec_ctx *, int);

    int sqlcipher_codec_ctx_set_pass(codec_ctx *, const void *, int, int);
    void sqlcipher_codec_get_keyspec(codec_ctx *, void **zKey, int *nKey);

    int sqlcipher_codec_ctx_set_pagesize(codec_ctx *, int);
    int sqlcipher_codec_ctx_get_pagesize(codec_ctx *);
    int sqlcipher_codec_ctx_get_reservesize(codec_ctx *);

    void sqlcipher_set_default_pagesize(int page_size);
    int sqlcipher_get_default_pagesize();

    void sqlcipher_set_default_kdf_iter(int iter);
    int sqlcipher_get_default_kdf_iter();

    int sqlcipher_codec_ctx_set_kdf_iter(codec_ctx *, int, int);
    int sqlcipher_codec_ctx_get_kdf_iter(codec_ctx *ctx, int);

    void* sqlcipher_codec_ctx_get_kdf_salt(codec_ctx *ctx);

    int sqlcipher_codec_ctx_set_fast_kdf_iter(codec_ctx *, int, int);
    int sqlcipher_codec_ctx_get_fast_kdf_iter(codec_ctx *, int);

    int sqlcipher_codec_ctx_set_cipher(codec_ctx *, const char *, int);
    const char* sqlcipher_codec_ctx_get_cipher(codec_ctx *ctx, int for_ctx);

    void* sqlcipher_codec_ctx_get_data(codec_ctx *);

    //void sqlcipher_exportFunc(sqlite3_context *, int, sqlite3_value **);

    void sqlcipher_set_default_use_hmac(int use);
    int sqlcipher_get_default_use_hmac();

    void sqlcipher_set_hmac_salt_mask(unsigned char mask);
    unsigned char sqlcipher_get_hmac_salt_mask();

    int sqlcipher_codec_ctx_set_use_hmac(codec_ctx *ctx, int use);
    int sqlcipher_codec_ctx_get_use_hmac(codec_ctx *ctx, int for_ctx);

    int sqlcipher_codec_ctx_set_flag(codec_ctx *ctx, unsigned int flag);
    int sqlcipher_codec_ctx_unset_flag(codec_ctx *ctx, unsigned int flag);
    int sqlcipher_codec_ctx_get_flag(codec_ctx *ctx, unsigned int flag, int for_ctx);

    const char* sqlcipher_codec_get_cipher_provider(codec_ctx *ctx);
    //int sqlcipher_codec_ctx_migrate(codec_ctx *ctx);
    int sqlcipher_codec_add_random(codec_ctx *ctx, const char *data, int random_sz);
    int sqlcipher_cipher_profile(sqlite3 *db, const char *destination);
    //static void sqlcipher_profile_callback(void *file, const char *sql, sqlite3_uint64 run_time);
    //static int sqlcipher_codec_get_store_pass(codec_ctx *ctx);
    //static void sqlcipher_codec_get_pass(codec_ctx *ctx, void **zKey, int *nKey);
    //static void sqlcipher_codec_set_store_pass(codec_ctx *ctx, int value);
    int sqlcipher_codec_fips_status(codec_ctx *ctx);
    const char* sqlcipher_codec_get_provider_version(codec_ctx *ctx);
}


// Fake sqlite3_file used to provide preloaded KDF salt to sqlcipher_codec_ctx_init() 
// routine.
struct FixedKdfFile {
    const struct sqlite3_io_methods *pMethods;
    uint8_t *kdfSalt;

    struct sqlite3_io_methods methods;
    
    static int read(sqlite3_file *fd, void *data, int iAmt, sqlite3_int64 iOfst);

    FixedKdfFile(uint8_t *kdfSalt_) : pMethods(&methods), kdfSalt(kdfSalt_) {
        memset(&methods, 0, sizeof(methods));
        methods.xRead = read;
    }
};


int FixedKdfFile::read(sqlite3_file *fd, void *data, int iAmt, sqlite3_int64 iOfst) {
    FixedKdfFile *f = reinterpret_cast<FixedKdfFile *>(fd);

    memcpy(data, f->kdfSalt, (iAmt > 16) ? 16 : iAmt);
    return SQLITE_OK;
}


CryptoContext::CryptoContext(File &file, const void *key, int keyLen, uint8_t *backupSalt,
        const char *cipherName, int pageSize, int kdfIter, CryptoHmacSetting useHmac)
        : m_ctx(nullptr), m_pageSize(0), m_reservedSize(0) {

    // SQLite library must be initialized before calling sqlcipher_activate(),
    // or it will cause a deadlock.
    sqlite3_initialize();
    sqlcipher_activate();

    // Check arguments.
    if (!key || keyLen <= 0) return;

    // XXX: fake BTree structure passed to sqlcipher_codec_ctx_init.
    // Member of such structure is assigned but never used by repair kit.
    int fakeDB[8];

    // Read KDF salt from file.
    uint8_t *kdfSalt;
    if (!backupSalt) {
        kdfSalt = (uint8_t *) alloca(16);
        file.read(kdfSalt, 0, 16);
    } else {
        kdfSalt = backupSalt;
    }

    // Fake sqlite3_file to pass KDF salt to sqlcipher_codec_ctx_init.
    FixedKdfFile kf(kdfSalt);

    // Initialize codec context.
    codec_ctx *codec = nullptr;
    int rc = sqlcipher_codec_ctx_init(&codec, reinterpret_cast<Db *>(fakeDB), nullptr, 
            reinterpret_cast<sqlite3_file *>(&kf), key, keyLen);
    if (rc != SQLITE_OK) return;
    m_ctx = codec;

    // Set cipher.
    if (cipherName) {
        rc = sqlcipher_codec_ctx_set_cipher(codec, cipherName, CIPHER_READWRITE_CTX);
        if (rc != SQLITE_OK) return;
    }

    // Set page size.
    if (pageSize > 0) {
        rc = sqlcipher_codec_ctx_set_pagesize(codec, pageSize);
        if (rc != SQLITE_OK) return;
    }

    // Set HMAC usage.
    if (useHmac != HMAC_DEFAULT) {
        rc = sqlcipher_codec_ctx_set_use_hmac(codec, (useHmac == HMAC_USE));
        if (rc != SQLITE_OK) return;
    }

    // Set KDF Iteration.
    if (kdfIter > 0) {
        rc = sqlcipher_codec_ctx_set_kdf_iter(codec, kdfIter, CIPHER_READWRITE_CTX);
        if (rc != SQLITE_OK) return;
    }

    // Update pager page size.
    m_pageSize = sqlcipher_codec_ctx_get_pagesize(codec);
    m_reservedSize = sqlcipher_codec_ctx_get_reservesize(codec);
}

CryptoContext::~CryptoContext() {
    if (m_ctx)
        sqlcipher_codec_ctx_free(&m_ctx);
    sqlcipher_deactivate();
}

bool CryptoContext::decode(int pageNo, void *data) {
    int rc;
    int offset = 0;
    unsigned char *pdata = (unsigned char *) data;
    unsigned char *buffer = (unsigned char *) sqlcipher_codec_ctx_get_data(m_ctx);

    rc = sqlcipher_codec_key_derive(m_ctx);
    if (rc != SQLITE_OK) return rc;

    if (pageNo == 1) {
        offset = 16;    // FILE_HEADER_SZ
        memcpy(buffer, "SQLite format 3", 16);
    }
    rc = sqlcipher_page_cipher(m_ctx, CIPHER_READ_CTX, pageNo, CIPHER_DECRYPT, m_pageSize - offset,
            pdata + offset, buffer + offset);
    if (rc != SQLITE_OK) {
        // LOG("Failed to decode page %d: %s", pageNo);
        return false;
    }
    memcpy(pdata, buffer, m_pageSize);

    return true;
}
