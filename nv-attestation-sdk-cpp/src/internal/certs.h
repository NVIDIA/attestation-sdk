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

#include <string>

namespace nvattestation
{
    const std::string RIM_ROOT_CERT = R"(-----BEGIN CERTIFICATE-----
MIICKTCCAbCgAwIBAgIQRdrjoA5QN73fh1N17LXicDAKBggqhkjOPQQDAzBFMQsw
CQYDVQQGEwJVUzEPMA0GA1UECgwGTlZJRElBMSUwIwYDVQQDDBxOVklESUEgQ29S
SU0gc2lnbmluZyBSb290IENBMCAXDTIzMDMxNjE1MzczNFoYDzIwNTMwMzA4MTUz
NzM0WjBFMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGTlZJRElBMSUwIwYDVQQDDBxO
VklESUEgQ29SSU0gc2lnbmluZyBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEuECyi9vNM+Iw2lfUzyBldHAwaC1HF7TCgp12QcEyUTm3Tagxwr48d55+K2VI
lWYIDk7NlAIQdcV/Ff7euGLI+Qauj93HsSI4WX298PpW54RTgz9tC+Q684caR/BX
WEeZo2MwYTAdBgNVHQ4EFgQUpaXrOPK4ZDAk08DBskn594zeZjAwHwYDVR0jBBgw
FoAUpaXrOPK4ZDAk08DBskn594zeZjAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwCgYIKoZIzj0EAwMDZwAwZAIwHGDyscDP6ihHqRvZlI3eqZ4YkvjE
1duaN84tAHRVgxVMvNrp5Tnom3idHYGW/dskAjATvjIx6VzHm/4e2GiZAyZEIUBD
OKPzp5ei/A0iUZpdvngenDwV8Qa/wGdiTmJ7Bp4=
-----END CERTIFICATE-----)";

    const std::string DEVICE_ROOT_CERT = R"(-----BEGIN CERTIFICATE-----
MIICCzCCAZCgAwIBAgIQLTZwscoQBBHB/sDoKgZbVDAKBggqhkjOPQQDAzA1MSIw
IAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklE
SUEwIBcNMjExMTA1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDUxIjAgBgNVBAMM
GU5WSURJQSBEZXZpY2UgSWRlbnRpdHkgQ0ExDzANBgNVBAoMBk5WSURJQTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABA5MFKM7+KViZljbQSlgfky/RRnEQScW9NDZF8SX
gAW96r6u/Ve8ZggtcYpPi2BS4VFu6KfEIrhN6FcHG7WP05W+oM+hxj7nyA1r1jkB
2Ry70YfThX3Ba1zOryOP+MJ9vaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwHQYDVR0OBBYEFFeF/4PyY8xlfWi3Olv0jUrL+0lfMB8GA1UdIwQY
MBaAFFeF/4PyY8xlfWi3Olv0jUrL+0lfMAoGCCqGSM49BAMDA2kAMGYCMQCPeFM3
TASsKQVaT+8S0sO9u97PVGCpE9d/I42IT7k3UUOLSR/qvJynVOD1vQKVXf0CMQC+
EY55WYoDBvs2wPAH1Gw4LbcwUN8QCff8bFmV4ZxjCRr4WXTLFHBKjbfneGSBWwA=
-----END CERTIFICATE-----)";
}