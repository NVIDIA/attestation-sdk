/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ear_status.h"

#include <string>

namespace nvattest {

bool ear_is_affirming(const nlohmann::json& ear) {
    if (!ear.is_object()) {
        return false;
    }
    const auto overall_status = ear.find("ear_status");
    if (overall_status == ear.end() || !overall_status->is_string() ||
        overall_status->get_ref<const std::string&>() != "affirming") {
        return false;
    }

    const auto submods = ear.find("submods");
    if (submods == ear.end() || !submods->is_object() || submods->empty()) {
        return false;
    }
    for (const auto& item : submods->items()) {
        const auto& submod = item.value();
        if (!submod.is_object()) {
            return false;
        }
        const auto status = submod.find("ear_status");
        if (status == submod.end() ||
            !status->is_string() ||
            status->get_ref<const std::string&>() != "affirming") {
            return false;
        }
    }
    return true;
}

} // namespace nvattest
