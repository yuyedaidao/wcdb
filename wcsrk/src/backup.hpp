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

#ifndef backup_hpp
#define backup_hpp

#include "util/value.hpp"
#include <stdio.h>
#include <map>
#include <string>
#include <memory>

typedef struct sqlite3 sqlite3;

class Backup
{
public:

    struct MasterEntry {
        enum Type { ENTRY_TABLE = 1, ENTRY_INDEX = 2 };

        uint32_t rootPage;
        Type type;
        std::string sql;
        std::string tableName;
    };
    typedef std::map<std::string, MasterEntry> MasterInfoMap;
    typedef std::map<std::string, PersistValue> MetaInfoMap;
    
    bool loadFromDatabase(sqlite3* db);

    bool saveToFile(const std::string& path, const void *pass, int passLen);
    bool loadFromFile(const std::string& path, const void *pass, int passLen);
    
    const MasterInfoMap & masterInfo() const { return m_masterInfo; }
    MetaInfoMap & metaInfo() { return m_metaInfo; }
    const MetaInfoMap & metaInfo() const { return m_metaInfo; }

private:
    MasterInfoMap m_masterInfo;
    MetaInfoMap m_metaInfo;
    uint8_t m_kdfSalt[16];
    // TODO: freeListCount
};

#endif /* backup_hpp */
