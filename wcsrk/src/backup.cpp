/*
 * Tencent is pleased to support the open source community by making
 * WCDB available.
 *
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *       https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "backup.hpp"
#include <cstdint>
#include <cstdio>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <alloca.h>


bool Backup::loadFromDatabase(sqlite3 *db) {
    MasterInfoMap newMap;
    sqlite3_stmt *stmt = nullptr;

    int rc = sqlite3_prepare_v2(db, "SELECT * FROM sqlite_master;", -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        // LOG(...)
        return false;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *typestr = (const char *) sqlite3_column_text(stmt, 1);
        MasterEntry::Type type;
        if (strcmp(typestr, "table") == 0)
            type = MasterEntry::ENTRY_TABLE;
        else if (strcmp(typestr, "index") == 0)
            type = MasterEntry::ENTRY_INDEX;
        else continue;

        int nameLen = sqlite3_column_bytes(stmt, 1);
        const char *name = (const char *) sqlite3_column_text(stmt, 1);
        
        // Skip system tables and indices.
        if (strncmp(name, "sqlite_", 7) == 0)
            continue;
        
        int tblNameLen = sqlite3_column_bytes(stmt, 2);
        const char *tblName = (const char *) sqlite3_column_text(stmt, 2);
        uint32_t rootPage = sqlite3_column_int64(stmt, 3);
        int sqlLen = sqlite3_column_bytes(stmt, 4);
        const char *sql = (const char *) sqlite3_column_text(stmt, 4);

        // Insert to map.
        newMap.emplace(std::string(name, nameLen), MasterEntry{ rootPage, type, 
                std::string(sql, sqlLen), std::string(tblName, tblNameLen) });
    }
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        // LOG(...)
        return false;
    }

    // Read KDF salt from file header.
    // TODO: it may cause race condition here since we don't get a file lock. 
    sqlite3_file *dbFile;
    rc = sqlite3_file_control(db, "main", SQLITE_FCNTL_FILE_POINTER, &dbFile);
    if (rc != SQLITE_OK) return false;

    rc = dbFile->pMethods->xRead(dbFile, m_kdfSalt, sizeof(m_kdfSalt), 0);
    if (rc != SQLITE_OK) return false;

    // Assign result to member field.
    m_masterInfo = std::move(newMap);
    return true;
}

// Backup serialization
#define MASTER_BACKUP_MAGIC     "WCmst\0"
#define MASTER_BACKUP_VERSION   1

#pragma pack(push, 1)
struct MasterFileHeader {
    char magic[6];
    uint16_t version;
    unsigned char kdfSalt[16];
    
    unsigned char iv[0];
};

struct MasterFileHeader2 {
    uint32_t entries;
    uint32_t metaEntries;
    //uint32_t freeListCount;
};

struct MasterFileEntry {
    uint32_t rootPage;
    uint8_t type;
    uint8_t nameLen;
    uint8_t tblNameLen;
    uint8_t reserved;
    uint16_t sqlLen;

    unsigned char data[0];
};

struct MetaFileEntry {
    uint16_t keyLen;
    unsigned char data[0];
};
#pragma pack(pop)


static int encodeVarint(int64_t value, uint8_t *buf) {
    uint8_t *p = buf;
    uint64_t v = static_cast<uint64_t>(value);  // force logical shift

    do {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        *p++ = b;
    } while (v);

    return p - buf;
}

static int decodeVarint(const uint8_t *buf, int64_t *value) {
    uint64_t v = 0;
    int i, swf;

    for (i = 0, swf = 0; i < 9; swf += 7) {
        uint8_t b = buf[i++];
        v |= (b & 0x7F) << swf;
        if (!(b & 0x80)) break;
    }

    *value = static_cast<int64_t>(v);
    return i;
}

inline static int encodeDouble(double value, uint8_t *buf) {
    memcpy(buf, &value, sizeof(double));
    return sizeof(double);
}

static bool deflateWrite(FILE *fp, z_streamp strm, const void *buf, unsigned len, EVP_CIPHER_CTX *ctx, bool flush) {
    uint8_t outBuf[2048];
    uint8_t outBuf2[2048];
    
    strm->next_in = (uint8_t *) buf;
    strm->avail_in = len;

    do {
        strm->next_out = outBuf;
        strm->avail_out = sizeof(outBuf);
        int rc = deflate(strm, flush ? Z_FINISH : Z_NO_FLUSH);
        if (rc == Z_STREAM_ERROR) return false;

        unsigned have = sizeof(outBuf) - strm->avail_out;
        if (ctx) {
            int outLen;
            if (!EVP_EncryptUpdate(ctx, outBuf2, &outLen, outBuf, have)) return false;
            if (fwrite(outBuf2, 1, outLen, fp) != (size_t) outLen) return false;
            if (flush) {
                if (!EVP_EncryptFinal_ex(ctx, outBuf2, &outLen)) return false;
                if (fwrite(outBuf2, 1, outLen, fp) != (size_t) outLen) return false;
            }
        } else {
            if (fwrite(outBuf, 1, have, fp) != have)
            {
                // LOG(...)
                return false;
            }
        }

    } while (strm->avail_out == 0);

    return true;
}

bool Backup::saveToFile(const std::string& path, const void *pass, int passLen) {
    FILE *fp = nullptr;
    z_stream zstrm = { 0 };
    EVP_CIPHER_CTX *ctx = nullptr;
    uint8_t *iv = nullptr;
    int ivLen = 0;
    bool evpInit = false;

    MasterFileHeader header;
    MasterFileHeader2 header2;

    // Prepare deflate stream.
    int rc = deflateInit(&zstrm, Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        // LOG(...)
        goto bail;
    }
    zstrm.data_type = Z_TEXT;

    // Open output file.
    fp = fopen(path.c_str(), "wb");
    if (!fp) {
        // LOG(...)
        goto bail;
    }

    // Prepare cipher key.
    if (pass && passLen > 0) {
        // Initialize OpenSSL if it's not done externally.
        if (!EVP_get_cipherbyname("aes-256-cbc")) {
            OpenSSL_add_all_algorithms();
            evpInit = true;
        }

        // Get cipher properties.
        const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-256-cbc");
        if (!cipher) goto bail;
        int keyLen = EVP_CIPHER_key_length(cipher);
        ivLen = EVP_CIPHER_iv_length(cipher);

        // Derive key.
        uint8_t *key = (uint8_t *) alloca(keyLen);
        PKCS5_PBKDF2_HMAC_SHA1((const char *) pass, passLen, m_kdfSalt, sizeof(m_kdfSalt), 3, keyLen, key);

        // Generate IV.
        if (ivLen > 0) {
            iv = (uint8_t *) alloca(ivLen);
            RAND_pseudo_bytes(iv, ivLen);
        }

        // Initialize cipher context.
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) goto bail;
        if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv))
            goto bail;
    }

    // Write header.
    memcpy(header.magic, MASTER_BACKUP_MAGIC, sizeof(header.magic));
    header.version = MASTER_BACKUP_VERSION;
    memcpy(header.kdfSalt, m_kdfSalt, sizeof(m_kdfSalt));
    if (fwrite(&header, sizeof(header), 1, fp) != 1)
        goto bail;

    // Write IV.
    if (iv && ivLen > 0) {
        if (fwrite(iv, ivLen, 1, fp) != 1)
            goto bail;
    }

    // Write encrypted header.
    header2.entries = m_masterInfo.size();
    header2.metaEntries = m_metaInfo.size();
    if (!deflateWrite(fp, &zstrm, &header2, sizeof(header2), ctx, false))
        goto bail;

    // Write all rows.
    for (const auto &info : m_masterInfo) {
        uint8_t inBuf[512 + sizeof(MasterFileEntry)];
        MasterFileEntry *entry = (MasterFileEntry *) inBuf;

        int nameLen = info.first.length();
        int tblNameLen = info.second.tableName.length();
        int sqlLen = info.second.sql.length();

        if (nameLen > 255 || tblNameLen > 255 || sqlLen > 65535) {
            // LOG("Too long");
            goto bail;
        }

        entry->rootPage = info.second.rootPage;
        entry->type = (uint8_t) info.second.type;
        entry->nameLen = (uint8_t) info.first.length();
        entry->tblNameLen = (uint8_t) info.second.tableName.length();
        entry->reserved = 0;
        entry->sqlLen = (uint16_t) info.second.sql.length();

        unsigned char *pData = entry->data;
        memcpy(pData, info.first.c_str(), nameLen + 1);
        pData += nameLen + 1;
        memcpy(pData, info.second.tableName.c_str(), tblNameLen + 1);
        pData += tblNameLen + 1;

        if (!deflateWrite(fp, &zstrm, inBuf, pData - inBuf, ctx, false))
            goto bail;

        if (!deflateWrite(fp, &zstrm, info.second.sql.c_str(), sqlLen + 1, ctx, false))
            goto bail;
    }

    // Write all meta entries.
    for (const auto &meta : m_metaInfo) {
        // Write key length and content.
        MetaFileEntry entry { static_cast<uint16_t>(meta.first.length()) };
        if (!deflateWrite(fp, &zstrm, &entry, sizeof(entry), ctx, false))
            goto bail;
        if (!deflateWrite(fp, &zstrm, meta.first.c_str(), entry.keyLen, ctx, false))
            goto bail;

        // Write TLV.
        Value::Type type = meta.second.getType();
        uint8_t buf[16];
        buf[0] = static_cast<uint8_t>(type);
        int len = 1;
        int writeBlob = false;

        switch (type) {
            int varintLen;

        case Value::TYPE_NULL:
            break;
        case Value::TYPE_INTEGER:
            varintLen = encodeVarint(meta.second.asInteger(), &buf[1]);
            buf[0] |= ((varintLen - 1) & 0x0F) << 4;
            len += varintLen;
            break;
        case Value::TYPE_FLOAT:
            len += encodeDouble(meta.second.asDouble(), &buf[1]);
            break;
        case Value::TYPE_TEXT:
        case Value::TYPE_BLOB:
            varintLen = encodeVarint(meta.second.getSize(), &buf[1]);
            buf[0] |= ((varintLen - 1) & 0x0F) << 4;
            len += varintLen;
            writeBlob = true;
            break;
        default:    // invalid type value
            goto bail;
        }

        if (!deflateWrite(fp, &zstrm, buf, len, ctx, false))
            goto bail;
        if (writeBlob && !deflateWrite(fp, &zstrm, meta.second.asBlob(),
                meta.second.getSize(), ctx, false))
            goto bail;
    }

    // Flush Z-stream.
    if (!deflateWrite(fp, &zstrm, nullptr, 0, ctx, true))
        goto bail;
    deflateEnd(&zstrm);

    // Cleanup.
    fclose(fp);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (evpInit) EVP_cleanup();

    return true;

bail:
    if (fp) fclose(fp);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (evpInit) EVP_cleanup();
    deflateEnd(&zstrm);
    return false;
}

static bool inflateRead(FILE *fp, z_streamp strm, void *buf, unsigned size, EVP_CIPHER_CTX *ctx)
{
    int ret;
    if (size == 0) return true;

    strm->next_out = (unsigned char *) buf;
    strm->avail_out = size;

    do {
        if (strm->avail_in == 0 && !feof(fp)) {
            unsigned char *inBuf = strm->next_in - strm->total_in;
            strm->total_in = 0;

            if (ctx) {
                uint8_t inBuf2[4096];
                ret = fread(inBuf2, 1, sizeof(inBuf2), fp);
                if (ret == 0) {
                    if (ferror(fp)) return false;
                    
                    if (feof(fp)) {
                        if (!EVP_DecryptFinal_ex(ctx, inBuf, &ret))
                            return false;
                    }
                } else {
                    if (!EVP_DecryptUpdate(ctx, inBuf, &ret, inBuf2, ret))
                        return false;
                }
            } else {
                ret = fread(inBuf, 1, 4096, fp);
                if (ret == 0 && ferror(fp))
                    return false;
            }

            strm->next_in = inBuf;
            strm->avail_in = ret;
        }

        ret = inflate(strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            return false;

    } while (strm->avail_out > 0 && ret != Z_STREAM_END);

    return strm->avail_out == 0;
}

bool Backup::loadFromFile(const std::string& path, const void *pass, int passLen) {
    FILE *fp = nullptr;
    z_stream zstrm = { 0 };
    unsigned entries, metaEntries;
    char *strBuf = nullptr;
    MasterInfoMap newMap;
    MetaInfoMap newMeta;
    int rc;
    bool evpInit = false;
    EVP_CIPHER_CTX *ctx = nullptr;

    // Allocate string buffer.
    strBuf = (char *) malloc(256 + 256 + 65536);
    if (!strBuf) goto bail;

    // Open file for reading.
    fp = fopen(path.c_str(), "rb");
    if (!fp) {
        // LOG(...)
        goto bail;
    }

    MasterFileHeader header;
    MasterFileHeader2 header2;

    // Read file header.
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        // LOG(...)
        goto bail;
    }
    if (memcmp(header.magic, MASTER_BACKUP_MAGIC, sizeof(header.magic)) != 0 ||
            header.version != MASTER_BACKUP_VERSION) {
        // LOG("Invalid format")
        goto bail;
    }

    // Prepare cipher key.
    if (pass && passLen > 0) {
        // Initialize OpenSSL if it's not done externally.
        if (!EVP_get_cipherbyname("aes-256-cbc")) {
            OpenSSL_add_all_algorithms();
            evpInit = true;
        }

        // Get cipher properties.
        const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-256-cbc");
        if (!cipher) goto bail;
        int keyLen = EVP_CIPHER_key_length(cipher);
        int ivLen = EVP_CIPHER_iv_length(cipher);

        // Derive key.
        uint8_t *key = (uint8_t *) alloca(keyLen);
        PKCS5_PBKDF2_HMAC_SHA1((const char *) pass, passLen, header.kdfSalt, sizeof(header.kdfSalt), 3, keyLen, key);

        // Read IV.
        uint8_t *iv;
        if (ivLen > 0) {
            iv = (uint8_t *) alloca(ivLen);
            if (fread(iv, ivLen, 1, fp) != 1) goto bail;
        }

        // Initialize cipher context.
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) goto bail;
        if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv))
            goto bail;
    }

    // Initialize zlib.
    rc = inflateInit(&zstrm);
    if (rc != Z_OK) {
        // LOG(...)
        return false;
    }
    uint8_t inBuf[4096 + 32];
    zstrm.next_in = inBuf;
    zstrm.avail_in = 0;

    // Read encrypted header.
    if (!inflateRead(fp, &zstrm, &header2, sizeof(header2), ctx))
        goto bail;
    entries = header2.entries;
    metaEntries = header2.metaEntries;

    // Read all entities.
    while (entries--) {
        // Read entity header.
        MasterFileEntry entry;
        if (!inflateRead(fp, &zstrm, &entry, sizeof(entry), ctx)) {
            // LOG(...)
            goto bail;
        }

        // Read names and SQL.
        if (!inflateRead(fp, &zstrm, strBuf, 
                entry.nameLen + entry.tblNameLen + entry.sqlLen + 3, ctx)) {
            // LOG(...)
            goto bail;
        }

        const char *name = strBuf;
        const char *tableName = name + entry.nameLen + 1;
        const char *sql = tableName + entry.tblNameLen + 1;
        if (name[entry.nameLen] != '\0' || tableName[entry.tblNameLen] != '\0'
                || sql[entry.sqlLen] != '\0') {
            // LOG("Invalid string. File corrupted.");
            goto bail;
        }

        // Add to map.
        newMap.emplace(std::string(name, entry.nameLen), MasterEntry{ entry.rootPage, 
                (MasterEntry::Type) entry.type, std::string(sql, entry.sqlLen), 
                std::string(tableName, entry.tblNameLen) });
    }
    free(strBuf);
    strBuf = nullptr;

    // Read all meta entries.
    while (metaEntries--) {
        // Read key and type.
        MetaFileEntry entry;
        char keyBuf[256];
        char *pKey = keyBuf;
        Value::Type type;
        PersistValue value;

        if (!inflateRead(fp, &zstrm, &entry, sizeof(entry), ctx))
            goto bail;
        if (entry.keyLen > 255) {
            pKey = (char *) malloc(entry.keyLen + 1);
            if (!pKey) goto bail;
        }
        if (!inflateRead(fp, &zstrm, pKey, entry.keyLen + 1, ctx))
            goto inner_bail;

        type = static_cast<Value::Type>(pKey[entry.keyLen] & 0x0F);

        // Read value.
        if (type == Value::TYPE_INTEGER || type == Value::TYPE_TEXT || type == Value::TYPE_BLOB) {
            uint8_t varintBuf[12];
            int varintLen = ((pKey[entry.keyLen] & 0xF0) >> 4) + 1;
            int64_t varint;

            if (!inflateRead(fp, &zstrm, varintBuf, varintLen, ctx))
                goto inner_bail;
            if (decodeVarint(varintBuf, &varint) != varintLen)
                goto inner_bail;
            
            if (type == Value::TYPE_INTEGER) {
                value = PersistValue(varint);
            } else if (type == Value::TYPE_TEXT) {
                size_t size = varint;
                std::unique_ptr<char[]> buf(new (std::nothrow) char [size]);
                if (!buf) goto inner_bail;

                if (!inflateRead(fp, &zstrm, buf.get(), size, ctx))
                    goto inner_bail;

                value = PersistValue(std::move(buf), size);
            } else if (type == Value::TYPE_BLOB) {
                size_t size = varint;
                std::unique_ptr<unsigned char[]> buf(new (std::nothrow) unsigned char [size]);
                if (!buf) goto inner_bail;

                if (!inflateRead(fp, &zstrm, buf.get(), size, ctx))
                    goto inner_bail;

                value = PersistValue(std::move(buf), size);
            }
        } else if (type == Value::TYPE_FLOAT) {
            double d;
            if (!inflateRead(fp, &zstrm, &d, sizeof(double), ctx))
                goto inner_bail;

            value = PersistValue(d);
        }

        newMeta.emplace(std::string(pKey, entry.keyLen), std::move(value));

        continue;
    inner_bail:
        if (pKey != keyBuf) free(pKey);
        goto bail;
    }

    inflateEnd(&zstrm);

    // Cleanup.
    fclose(fp);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (evpInit) EVP_cleanup();

    m_masterInfo = std::move(newMap);
    m_metaInfo = std::move(newMeta);
    memcpy(m_kdfSalt, header.kdfSalt, sizeof(m_kdfSalt));
    return true;

bail:
    if (fp) fclose(fp);
    free(strBuf);
    inflateEnd(&zstrm);
    return false;
}
