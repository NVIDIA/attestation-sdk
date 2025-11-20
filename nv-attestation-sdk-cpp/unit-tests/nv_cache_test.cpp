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

#include <thread>
#include <future>
#include <chrono>

#include "nv_attestation/nv_cache.h"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"

#include "gtest/gtest.h"

using namespace nvattestation;

class NvCacheTest : public ::testing::Test {
    protected:
        NvCache m_cache;
        
        NvCacheTest() : m_cache(std::make_shared<NvCacheOptions>(1024*1024, 60)) {}
};

TEST_F(NvCacheTest, TestPutAndGet) {
    Error err = m_cache.put("test", std::make_shared<int>(1), 1024);
    ASSERT_EQ(err, Error::Ok);
    std::shared_ptr<void> value;
    err = m_cache.get("test", value);
    std::shared_ptr<int> actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(err, Error::Ok);
    ASSERT_EQ(*actual_value, 1);
}

TEST_F(NvCacheTest, TestPutKeyExists) {
    Error err = m_cache.put("test", std::make_shared<int>(1), 1024);
    ASSERT_EQ(err, Error::Ok);
    err = m_cache.put("test", std::make_shared<int>(2), 1024);
    ASSERT_EQ(err, Error::Ok);
    std::shared_ptr<void> value;
    err = m_cache.get("test", value);
    ASSERT_EQ(err, Error::Ok);
    std::shared_ptr<int> actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(*actual_value, 2);
}

TEST_F(NvCacheTest, TestPutAndRemove) {
    Error err = m_cache.put("test", std::make_shared<int>(1), 1024);
    ASSERT_EQ(err, Error::Ok);
    m_cache.remove("test");
    std::shared_ptr<void> value;
    err = m_cache.get("test", value);
    ASSERT_EQ(err, Error::CacheObjectNotFound);
}

TEST_F(NvCacheTest, TestLruEviction) {
    /*
        put test
        put test2
        put test3 // should evict test - lru eviction based on access

        put test3 with different value 
        put test4 // should evict test - lru eviction based on insertion order

    */
    
    Error err = m_cache.put("test", std::make_shared<int>(1), 1024*512);
    ASSERT_EQ(err, Error::Ok);
    err = m_cache.put("test2", std::make_shared<int>(2), 1024*512);
    ASSERT_EQ(err, Error::Ok); 
    
    // get an existing key and test lru eviction
    std::shared_ptr<void> value;
    err = m_cache.get("test", value);
    ASSERT_EQ(err, Error::Ok);
    std::shared_ptr<int> actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(*actual_value, 1);

    // should evict test2
    err = m_cache.put("test3", std::make_shared<int>(3), 1024*512);
    ASSERT_EQ(err, Error::Ok); 

    err = m_cache.get("test2", value);
    ASSERT_EQ(err, Error::CacheObjectNotFound);

    // check that test3 and test are present
    err = m_cache.get("test3", value);
    ASSERT_EQ(err, Error::Ok);
    actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(*actual_value, 3);

    err = m_cache.get("test", value);
    ASSERT_EQ(err, Error::Ok);
    actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(*actual_value, 1);

    // put an existing key and test lru eviction
    err = m_cache.put("test3", std::make_shared<int>(4), 1024*512);
    ASSERT_EQ(err, Error::Ok);

    // should evict test
    err = m_cache.put("test4", std::make_shared<int>(4), 1024*512);
    ASSERT_EQ(err, Error::Ok);

    err = m_cache.get("test", value);
    ASSERT_EQ(err, Error::CacheObjectNotFound);

    err = m_cache.get("test3", value);
    ASSERT_EQ(err, Error::Ok);
    actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(*actual_value, 4);

    err = m_cache.get("test4", value);
    ASSERT_EQ(err, Error::Ok);
    actual_value = std::static_pointer_cast<int>(value);
    ASSERT_EQ(*actual_value, 4);
}

TEST(NvShortExpiryCacheTest, TestExpiryEviction) {
    /*
        cache expiry is 3 seconds
        put 1
        sleep 2 seconds
        put 2 
        get 1 // should be found
        sleep 1 second
        put 3 // should evict 1
    */
    NvCache cache(std::make_shared<NvCacheOptions>(1024*1024, 3));
    Error err = cache.put("test", std::make_shared<int>(1), 1024*512);
    ASSERT_EQ(err, Error::Ok);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    err = cache.put("test2", std::make_shared<int>(2), 1024*512);
    ASSERT_EQ(err, Error::Ok);

    std::shared_ptr<void> value;
    err = cache.get("test", value);
    ASSERT_EQ(err, Error::Ok);
    ASSERT_EQ(*(std::static_pointer_cast<int>(value)), 1);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // should evict test, even though it is more recently used than test2
    // because it is expired
    err = cache.put("test3", std::make_shared<int>(3), 1024*512);
    ASSERT_EQ(err, Error::Ok);

    err = cache.get("test", value);
    ASSERT_EQ(err, Error::CacheObjectNotFound);
    err = cache.get("test2", value);
    ASSERT_EQ(err, Error::Ok);
    ASSERT_EQ(*(std::static_pointer_cast<int>(value)), 2);
    err = cache.get("test3", value);
    ASSERT_EQ(err, Error::Ok);
    ASSERT_EQ(*(std::static_pointer_cast<int>(value)), 3);
}

TEST_F(NvCacheTest, MultipleThreads) {
    /* 
        thread 1: put 1, keep looping for get 2 for 100 times
        with 100ms sleep, remove 2, keep looping until 1 is removed
        for 100 times with 100ms sleep, exit

        thread 2: put 2, keep looping for get 1 for 100 times
        with 100ms sleep, remove 1, keep looping until 2 is removed
        for 100 times with 100ms sleep, exit
    */
    std::future<Error> thread1 = std::async(std::launch::async, [&]() -> Error {
        m_cache.put("test", std::make_shared<int>(1), 1024);

        int loops = 0;
        std::shared_ptr<void> value;
        Error err;
        while (loops < 100) {
            err = m_cache.get("test2", value);
            if (err == Error::Ok) {
                break;
            }
            if (err == Error::CacheObjectNotFound) {
                loops++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            return err;
        }

        if (loops == 100) {
            LOG_ERROR("Thread 1 failed to get test2 even after 100 loops");
            return Error::InternalError;
        }

        if (*(std::static_pointer_cast<int>(value)) != 2) {
            LOG_ERROR("Thread 1 got wrong value for test2: " << value);
            return Error::InternalError;
        }

        m_cache.remove("test2");

        loops = 0;
        while (loops < 100) {
            err = m_cache.get("test", value);
            if (err == Error::CacheObjectNotFound) {
                break;
            }
            if (err == Error::Ok) {
                loops++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            return err;
        }

        if (loops == 100) {
            LOG_ERROR("Thread 1 failed to see test deleted even after 100 loops");
            return Error::InternalError;
        }

        return Error::Ok;
    });

    std::future<Error> thread2 = std::async(std::launch::async, [&]() -> Error {
        m_cache.put("test2", std::make_shared<int>(2), 1024);

        int loops = 0;
        std::shared_ptr<void> value;
        Error err;
        while (loops < 100) {
            err = m_cache.get("test", value);
            if (err == Error::Ok) {
                break;
            }
            if (err == Error::CacheObjectNotFound) {
                loops++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            return err;
        }

        if (loops == 100) {
            LOG_ERROR("Thread 2 failed to get test even after 100 loops");
            return Error::InternalError;
        }

        if (*(std::static_pointer_cast<int>(value)) != 1) {
            LOG_ERROR("Thread 2 got wrong value for test: " << value);
            return Error::InternalError;
        }

        m_cache.remove("test");

        loops = 0;
        while (loops < 100) {
            err = m_cache.get("test2", value);
            if (err == Error::CacheObjectNotFound) {
                break;
            }
            if (err == Error::Ok) {
                loops++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            return err;
        }

        if (loops == 100) {
            LOG_ERROR("Thread 2 failed to see test2 deleted even after 100 loops");
            return Error::InternalError;
        }

        return Error::Ok;
    });

    Error err = thread1.get();
    ASSERT_EQ(err, Error::Ok);
    err = thread2.get();
    ASSERT_EQ(err, Error::Ok);
}


