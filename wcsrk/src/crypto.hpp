#ifndef crypto_hpp
#define cryptp_hpp

#include <cstdint>
#include "util/File.hpp"


// Forward declearations from SQLCipher
typedef struct codec_ctx codec_ctx;


enum CryptoHmacSetting {
    HMAC_DEFAULT = -1,
    HMAC_DONT_USE,
    HMAC_USE,
};

class CryptoContext {
public:
    CryptoContext(File &file, const void *key, int keyLen, uint8_t *backupSalt,
            const char *cipherName = nullptr, int pageSize = 0, int kdfIter = 0,
            CryptoHmacSetting useHmac = HMAC_DEFAULT);

    ~CryptoContext();

    bool decode(int pageNo, void *data);

    bool valid() const { return m_ctx && m_pageSize; }
    int getPageSize() const { return m_pageSize; }
    int getReservedSize() const { return m_reservedSize; }

private:
    codec_ctx *m_ctx;
    int m_pageSize;
    int m_reservedSize;
};

#endif
