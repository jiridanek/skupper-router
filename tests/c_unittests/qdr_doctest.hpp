/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef QDR_DOCTEST
#define QDR_DOCTEST

// this must be defined globally
// https://github.com/onqtam/doctest/blob/master/doc/markdown/configuration.md#doctest_config_treat_char_star_as_string
#define DOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING
#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS

#include "catch2/catch_amalgamated.hpp"

// compatibility define for doctest tests to work with catch2

// https://github.com/catchorg/Catch2/issues/929#issuecomment-321928622
#define CHECK_MESSAGE(cond, ...) [&] { CAPTURE(__VA_ARGS__); CHECK(cond); }()
#define REQUIRE_MESSAGE(cond, ...) [&] { CAPTURE(__VA_ARGS__); REQUIRE(cond); }()

#endif  // QDR_DOCTEST
