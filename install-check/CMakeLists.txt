# Copyright © 2026 Khrustal & Mann
#              MELBOURNE, VICTORIA, AUSTRALIA, 3000
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# The downstream project.  Stage 5 step 14.
#
# This is NOT part of the MSCS build.  It is never add_subdirectory()'d; it is
# configured from scratch, by run_install_check.cmake, against nothing but an
# install prefix -- which is the only way to find out whether the install tree
# stands on its own.  A check that ran inside the parent build would have the
# source tree, the sibling targets and every include path already in scope, and
# would therefore pass no matter what the install rules staged.
#
# LANGUAGES C.  Everything that ships is a flat C surface; a C++ project here
# would prove a weaker claim and would quietly tolerate a header that only a
# C++ compiler accepts.
cmake_minimum_required(VERSION 3.24)
project(TargetcoreInstallCheck LANGUAGES C)

# The one line a third party writes.  If the config package, its version file,
# its targets file or its find_dependency(Msgcore) is missing or wrong, this
# fails here -- before a compiler runs -- and says which.
find_package(Targetcore REQUIRED)

add_executable(installed_consumer consumer.c)

# Msgcore::msgcore is named EXPLICITLY as well as arriving transitively through
# Targetcore::targetcore.  consumer.c calls msgcore_mgr_* directly, and a
# consumer that only reached the sibling by accident of transitivity would not
# notice if Msgcore_c.h or the msgcore import library never got installed.
target_link_libraries(installed_consumer PRIVATE
                      Targetcore::targetcore
                      Msgcore::msgcore)

# Report what was resolved, so a failing run says WHICH library it found rather
# than only that something did not work.
get_target_property(_p2p_loc Targetcore::targetcore IMPORTED_LOCATION_NOCONFIG)
if(NOT _p2p_loc)
    get_target_property(_p2p_loc Targetcore::targetcore IMPORTED_LOCATION_RELEASE)
endif()
if(NOT _p2p_loc)
    get_target_property(_p2p_loc Targetcore::targetcore IMPORTED_LOCATION_DEBUG)
endif()
message(STATUS "install-check: Targetcore ${Targetcore_VERSION} -> ${_p2p_loc}")
message(STATUS "install-check: Msgcore    ${Msgcore_VERSION}")

# The version the config package advertises must equal the version the SHIPPED
# HEADER declares. They are produced by two different mechanisms -- the config
# file from a regex over the version header at configure time, the macro from
# the header itself -- and nothing else compares them.
#
# This is not hypothetical: the first draft of that regex stripped every
# non-digit from the #define line, which turned "TARGETCORE_VERSION_MAJOR 0"
# into 20, because the digit in "P2P" counts too. The package then advertised
# 20.29.20 and find_package(Targetcore 0.9.0) would have accepted it while
# find_package(Targetcore 1.0) would have accepted it as well. Both libraries
# still worked perfectly; only the number was a lie, and a version number that
# lies is worse than no version number, because a consumer acts on it.
foreach(_pkg Targetcore Msgcore)
    string(TOUPPER "${_pkg}" _PKG)
    file(STRINGS "${${_pkg}_DIR}/../../../include/${_pkg}_version.h" _vs
         REGEX "^#define[ \t]+${_PKG}_VERSION_STRING")
    string(REGEX REPLACE "^.*\"([0-9]+)\\.([0-9]+)\\.([0-9]+).*$" "\\1.\\2.\\3"
           _vs "${_vs}")
    if(NOT "${${_pkg}_VERSION}" STREQUAL "${_vs}")
        message(FATAL_ERROR
                "install-check: ${_pkg} config package advertises version "
                "'${${_pkg}_VERSION}' but the installed ${_pkg}_version.h "
                "declares '${_vs}'. The package metadata and the shipped "
                "header disagree about what this artifact is.")
    endif()
    message(STATUS "install-check: ${_pkg} version agrees with its header (${_vs})")
endforeach()
