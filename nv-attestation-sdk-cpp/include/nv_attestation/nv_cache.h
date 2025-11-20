/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <list>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <string>

#include "nv_attestation/error.h"

namespace nvattestation {

class NvCacheOptions {
    public: 
        static constexpr uint64_t DEFAULT_MAX_SIZE = 1024ULL * 1024;  // 1MB
        static constexpr time_t DEFAULT_TTL = 60 * 60;  // 1 hour

        uint64_t max_size_bytes;
        time_t ttl_seconds;
        NvCacheOptions(uint64_t max_size, time_t ttl_seconds) : max_size_bytes(max_size), ttl_seconds(ttl_seconds) {}
        NvCacheOptions() : max_size_bytes(DEFAULT_MAX_SIZE), ttl_seconds(DEFAULT_TTL) {}
};

class INvCache {

    public:
        virtual ~INvCache() = default;
        virtual Error put(const std::string& key, std::shared_ptr<void> value, uint64_t size_bytes) = 0;
        virtual Error get(const std::string& key, std::shared_ptr<void>& out_value) = 0;
        virtual void remove(const std::string& key) = 0;
        virtual void clear() = 0;
};

class NvCache : public INvCache {
    public:
        // same ttl applied to all objects
        // o(1) get, put, remove
        NvCache(const std::shared_ptr<NvCacheOptions>& options);
        ~NvCache();

        // T must be copyable
        Error put(const std::string& key, std::shared_ptr<void> value, uint64_t size_bytes) override;
        Error get(const std::string& key, std::shared_ptr<void>& out_value) override;
        void remove(const std::string& key) override;
        void clear() override;
    private: 
        class NvCacheObject {
            public:
                std::shared_ptr<void> m_value;
                uint64_t m_size_bytes;
                time_t m_expiry_time;
                std::list<std::string>::iterator m_lru_node_ptr;
                std::list<std::string>::iterator m_insertion_node_ptr;
        };

        std::unordered_map<std::string, NvCacheObject> m_cache;
        // if cache is full and no object has expired, to track which objects to evict first
        std::list<std::string> m_lru_list;
        // if cache is full, to track which objects to expire first
        std::list<std::string> m_insertion_list;

        uint64_t m_current_size_bytes = 0;
        std::mutex m_mutex;

        std::shared_ptr<NvCacheOptions> m_options;

        Error remove_helper(const std::string& key);
};


} // namespace nvattestation