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

#ifndef value_hpp
#define value_hpp

#include <vector>
#include <string>
#include <memory>
#include <cstdint>

class Value {
public:
    enum Type {
        TYPE_NULL = 0,
        TYPE_INTEGER,
        TYPE_FLOAT,
        TYPE_TEXT,
        TYPE_BLOB,
    };

    Value(std::nullptr_t = nullptr) : m_type(TYPE_NULL) {}

    template <typename IntType>
    Value(IntType value, typename std::enable_if<std::is_integral<IntType>::value>::type* = 0) 
            : m_type(TYPE_INTEGER) { m_value.i = static_cast<int64_t>(value); }

    template <typename FloatType>
    Value(FloatType value, typename std::enable_if<std::is_floating_point<FloatType>::value>::type* = 0)
            : m_type(TYPE_FLOAT) { m_value.d = static_cast<double>(value); }
    
    Value(const char *str, uint32_t len) : m_type(TYPE_TEXT) { 
        m_value.buf.buf = (const uint8_t *) str; 
        m_value.buf.len = len;
    }
    
    Value(const unsigned char *blob, uint32_t len) : m_type(TYPE_BLOB) { 
        m_value.buf.buf = blob;
        m_value.buf.len = len;
    }

    Value(Value &&rhs) : m_type(rhs.m_type) {
        rhs.m_type = TYPE_NULL;
        m_value = rhs.m_value;
    }

    Value & operator= (Value &&rhs) {
        std::swap(m_type, rhs.m_type);
        std::swap(m_value, rhs.m_value);
        return *this;
    }

    Type getType() const { return m_type; }

    size_t getSize() const;
    int64_t asInteger() const;
    double asDouble() const;
    const char *asText() const;
    const unsigned char *asBlob() const;

private:
    Type m_type;
    union {
        int64_t i;
        double d;
        struct {
            const uint8_t *buf;
            uint32_t len;
        } buf;
    } m_value;
};
typedef std::vector<Value> Values;


class PersistValue : public Value {
public:
    PersistValue(std::nullptr_t = nullptr) : Value(nullptr) {}
    
    template <typename IntType>
    PersistValue(IntType value, typename std::enable_if<std::is_integral<IntType>::value>::type* = 0)
            : Value(value) {}
    
    template <typename FloatType>
    PersistValue(FloatType value, typename std::enable_if<std::is_floating_point<FloatType>::value>::type* = 0)
            : Value(value) {}

    PersistValue(const std::string &str);
    PersistValue(const char *str, uint32_t len);
    PersistValue(std::unique_ptr<char[]> str, uint32_t len);

    PersistValue(const unsigned char *blob, uint32_t len);
    PersistValue(std::unique_ptr<unsigned char[]> blob, uint32_t len);

    PersistValue(PersistValue &&) = default;
    PersistValue & operator= (PersistValue &&) = default;

    ~PersistValue();
};

#endif /* value_hpp */
