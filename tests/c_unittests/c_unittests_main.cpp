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

#define DOCTEST_CONFIG_IMPLEMENT
#include "qdr_doctest.hpp"
#include "cpp_stub.h"
#include "qdr_stubbing_probe.hpp"

#include <cstdio>
#include <cstdlib>

bool check_stubbing_works()
{

#if (defined(_FORTIFY_SOURCE))
    // https://stackoverflow.com/questions/12201625/disable-using-sprintf-chk
    // Ubuntu with -O1+, https://stackoverflow.com/questions/34907503/gcc-fread-chk-warn-warning
    return false; // special checked glibc functions were substituted
#endif
#if (defined(__s390__) || defined(__s390x__) || defined(__zarch__))
    return false; // cpp-stub does not support
#endif

    {
        Stub stub;
        stub.set(probe, +[](int) -> int { return 42; });
        if (probe(0) != 42) {
            return false;
        }
    }
    {
        Stub stub;
        stub.set(abs, +[](int) -> int { return 24; });
        if (probe(0) != 24) {
            return false;
        }
    }

    return true;
}

// https://github.com/doctest/doctest/blob/master/doc/markdown/main.md
int main(int argc, char** argv)
{
    Catch::Session session; // There must be exactly one instance

    // writing to session.configData() here sets defaults
    // this is the preferred way to set them

    int returnCode = session.applyCommandLine( argc, argv );
    if( returnCode != 0 ) // Indicates a command line error
        return returnCode;

    // writing to session.configData() or session.Config() here
    // overrides command line args
    // only do this if you know you need to

    if (!check_stubbing_works()) {
#ifdef QD_REQUIRE_STUBBING_WORKS
        fprintf(stderr, "QD_REQUIRE_STUBBING_WORKS was defined, but stubbing doesn't work\n");
        abort();
#else
        fprintf(stderr, "Stubbing doesn't work. Define QD_REQUIRE_STUBBING_WORKS to get an abort()\n");
#endif
        session.configData().testsOrTags.insert(session.configData().testsOrTags.begin(), "~stubbed");
    }

    int numFailed = session.run();

    // numFailed is clamped to 255 as some unices only use the lower 8 bits.
    // This clamping has already been applied, so just return it here
    // You can also do any post run clean-up here
    return numFailed;
}
