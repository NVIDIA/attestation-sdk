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

#ifndef REGORUS_WRAPPER_HPP
#define REGORUS_WRAPPER_HPP

#include <memory>
#include <variant>

#include "regorus.ffi.hpp"

namespace regorus {

    class Result {
    public:

	operator bool() const { return result.status == RegorusStatus::RegorusStatusOk; }
	bool operator !() const { return result.status != RegorusStatus::RegorusStatusOk; }

	const char* output() const {
	    if (*this && result.output != nullptr) {
		return result.output;
	    } 
		return "";
	}
	
	const char* error() const {
	    if (!*this && result.error_message != nullptr) {
		return result.error_message;
	    } 
		return "";
	}

	~Result() {
	    regorus_result_drop(result);
	}

	// Move constructor that avoids the "from" object from deallocating the same handles
	Result(Result&& other) noexcept : result(other.result) {
		other.result.output        = nullptr;
		other.result.error_message = nullptr;
		other.result.status		   = RegorusStatus::RegorusStatusError;
	}

    private:
	friend class Engine;
	RegorusResult result;
	Result(RegorusResult result) : result(result) {}	
	Result(const Result&) = delete;
    };
    
    class Engine {
    public:
	Engine() : Engine(regorus_engine_new()) {}

	std::unique_ptr<Engine> clone() const {
	    return std::unique_ptr<Engine>(new Engine(regorus_engine_clone(engine)));
	}

	Result set_rego_v0(bool enable) {
        return Result(regorus_engine_set_rego_v0(engine, enable));
	}

	Result add_policy(const char* path, const char* policy) {
	    return Result(regorus_engine_add_policy(engine, path, policy));
	}
	
	Result add_policy_from_file(const char* path) {
	    return Result(regorus_engine_add_policy_from_file(engine, path));
	}
	
	Result add_data_json(const char* data) {
	    return Result(regorus_engine_add_data_json(engine, data));
	}
	
	Result add_data_from_json_file(const char* path) {
	    return Result(regorus_engine_add_data_from_json_file(engine, path));
	}
	
	Result set_input_json(const char* input) {
	    return Result(regorus_engine_set_input_json(engine, input));
	}
	
	Result set_input_from_json_file(const char* path) {
	    return Result(regorus_engine_set_input_from_json_file(engine, path));
	}

	Result eval_query(const char* query) {
	    return Result(regorus_engine_eval_query(engine, query));
	}
	
	Result eval_rule(const char* rule) {
	    return Result(regorus_engine_eval_rule(engine, rule));
	}
	
	Result set_enable_coverage(bool enable) {
		return Result(regorus_engine_set_enable_coverage(engine, enable));
	}
	
	Result clear_coverage_data() {
            return Result(regorus_engine_clear_coverage_data(engine));
	}
	
	Result get_coverage_report() {
            return Result(regorus_engine_get_coverage_report(engine));
	}
	
	Result get_coverage_report_pretty() {
            return Result(regorus_engine_get_coverage_report_pretty(engine));
	}
	
	~Engine() {
	    regorus_engine_drop(engine);
	}

private:
	RegorusEngine *engine;
	Engine(RegorusEngine *engine) : engine(engine) {}
	Engine(const Engine &) = delete;
	Engine(Engine &&) = delete;
	Engine &operator=(const Engine &) = delete;
	};
}

#endif // REGORUS_WRAPPER_HPP