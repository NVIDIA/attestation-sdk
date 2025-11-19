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

#include <time.h>
#include <iostream>
#include <string> 

#include "nv_attestation/nv_cache.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"

namespace nvattestation {

    NvCache::NvCache(const std::shared_ptr<NvCacheOptions>& options) {
        if (options == nullptr) {
            m_options = std::make_shared<NvCacheOptions>();
        } else {
            m_options = options;
        }
    }   

    Error NvCache::put(const std::string& key, std::shared_ptr<void> value, uint64_t size_bytes) {
        if (size_bytes > m_options->max_size_bytes) {
            LOG_ERROR("A single object with key "<< key << " and size " << size_bytes << " is too large to fit in the cache");
            LOG_ERROR("Cache size: " << m_current_size_bytes << " bytes");
            return Error::BadArgument;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_cache.find(key) != m_cache.end()) {
            remove_helper(key);
        }

        while(!m_insertion_list.empty() && m_current_size_bytes + size_bytes > m_options->max_size_bytes) {
            std::string oldest_key = m_insertion_list.back();
            if (m_cache[oldest_key].m_expiry_time > time(nullptr)) {
                break;
            }
            remove_helper(oldest_key);
        }

        while(!m_lru_list.empty() && m_current_size_bytes + size_bytes > m_options->max_size_bytes) {
            std::string oldest_key = m_lru_list.back();
            remove_helper(oldest_key);
        }

        m_current_size_bytes += size_bytes;
        m_lru_list.push_front(key);
        m_insertion_list.push_front(key);

        m_cache[key] = NvCacheObject{
            value, 
            size_bytes, 
            time(nullptr) + m_options->ttl_seconds, 
            m_lru_list.begin(), 
            m_insertion_list.begin(),
        };
        return Error::Ok;
    }

    Error NvCache::get(const std::string& key, std::shared_ptr<void>& out_value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_cache.find(key) == m_cache.end()) {
            LOG_DEBUG("Cache object not found for key: " << key);
            return Error::CacheObjectNotFound;
        }
        if (m_cache[key].m_expiry_time <= time(nullptr)) {
            LOG_DEBUG("Cache object expired for key: " << key);
            return Error::CacheObjectNotFound;
        }
        out_value = m_cache[key].m_value;

        m_lru_list.splice(m_lru_list.begin(), m_lru_list, m_cache[key].m_lru_node_ptr);

        return Error::Ok;
    }

    void NvCache::remove(const std::string& key) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_cache.find(key) == m_cache.end()) {
            LOG_DEBUG("Cache object not found for key: " << key);
            return;
        }
        m_current_size_bytes -= m_cache[key].m_size_bytes;
        m_lru_list.erase(m_cache[key].m_lru_node_ptr);
        m_insertion_list.erase(m_cache[key].m_insertion_node_ptr);
        m_cache.erase(key);
    }

    Error NvCache::remove_helper(const std::string& key) {
        m_current_size_bytes -= m_cache[key].m_size_bytes;
        m_lru_list.erase(m_cache[key].m_lru_node_ptr);
        m_insertion_list.erase(m_cache[key].m_insertion_node_ptr);
        m_cache.erase(key);
        return Error::Ok;
    }

    void NvCache::clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cache.clear();
        m_lru_list.clear();
        m_insertion_list.clear();
        m_current_size_bytes = 0;
    }

    NvCache::~NvCache() {
    }

}