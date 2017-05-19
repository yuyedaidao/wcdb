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

#include "value.hpp"
#include <cstdlib>

size_t Value::getSize() const {
    switch (m_type) {
    case TYPE_INTEGER:  return sizeof(int64_t);
    case TYPE_FLOAT:    return sizeof(double);
    case TYPE_TEXT:
    case TYPE_BLOB:     return m_value.buf.len;
    case TYPE_NULL:
    default:            return 0;
    }
}

int64_t Value::asInteger() const {
    switch (m_type) {
    case TYPE_INTEGER:  return m_value.i;
    case TYPE_FLOAT:    return static_cast<int64_t>(m_value.d);
    case TYPE_TEXT:     return strtoll((const char *) m_value.buf.buf, nullptr, 0);
    case TYPE_BLOB:
    case TYPE_NULL:
    default:            return 0;
    }
}

double Value::asDouble() const {
    switch (m_type) {
    case TYPE_INTEGER:  return static_cast<double>(m_value.i);
    case TYPE_FLOAT:    return m_value.d;
    case TYPE_TEXT:     return strtod((const char *) m_value.buf.buf, nullptr);
    case TYPE_BLOB:
    case TYPE_NULL:
    default:            return 0.0;
    }
}

const char *Value::asText() const {
    return (m_type == TYPE_TEXT) ? (const char *) m_value.buf.buf : "";
}

const unsigned char *Value::asBlob() const {
    return (m_type == TYPE_TEXT || m_type == TYPE_BLOB) ?
            m_value.buf.buf : nullptr;
}


PersistValue::PersistValue(const std::string &str) 
        : Value((char *) malloc(str.size() + 1), str.size()) {
    char *buf = const_cast<char *>(asText());
    memcpy(buf, str.c_str(), str.size() + 1);
}

PersistValue::PersistValue(const char *str, uint32_t len)
        : Value(new char[len + 1], len) {
    char *buf = const_cast<char *>(asText());
    memcpy(buf, str, len);
    buf[len] = '\0';
}

PersistValue::PersistValue(std::unique_ptr<char[]> str, uint32_t len)
        : Value(str.release(), len) {}

PersistValue::PersistValue(const unsigned char *blob, uint32_t len)
        : Value(new unsigned char[len], len) {
    unsigned char *buf = const_cast<unsigned char *>(asBlob());
    memcpy(buf, blob, len);
}

PersistValue::PersistValue(std::unique_ptr<unsigned char[]> blob, uint32_t len)
        : Value(blob.release(), len) {}

PersistValue::~PersistValue() {
    Type type = getType();
    if (type == TYPE_TEXT) {
        delete[] const_cast<char *>(asText());
    } else if (type == TYPE_BLOB) {
        delete[] const_cast<unsigned char *>(asBlob());
    }
}
