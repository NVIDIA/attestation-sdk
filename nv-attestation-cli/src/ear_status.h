/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <nlohmann/json.hpp>

namespace nvattest {

bool ear_is_affirming(const nlohmann::json& ear);

} // namespace nvattest
