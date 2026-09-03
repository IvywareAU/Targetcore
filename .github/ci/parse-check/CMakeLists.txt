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
# ---------------------------------------------------------------------------
# parse-check -- a STUB parent project, for CI only. Never build what it
# generates, and never use it as a template for consuming TargetCore.
#
# ../../../CMakeLists.txt is a COMPONENT script, not a project: Readme.md
# "CMake (in-tree)" says so, and it opens straight into set()/add_library()
# with no cmake_minimum_required() and no project(). It also expects the
# targets `msgcore` and `p2pplatform` to already exist, and those live in
# sibling repositories that are not published with this one. So `cmake -S .`
# on the repository root cannot work, by design.
#
# This file supplies the two things the component script assumes -- a project
# context and the two target names -- and NOTHING ELSE, so that CI can at least
# run the real CMakeLists.txt through CMake's parser and generator.
#
# WHAT CONFIGURING THIS PROVES
#   * ../../../CMakeLists.txt is syntactically valid CMake, and every command
#     and generator expression in it evaluates for a real generator.
#   * Every source file it names for the WIN32 branch exists at the path it
#     names. CMake errors at generate time on a missing source ("Cannot find
#     source file"), so this is a real check, not a lint.
#   * The target it declares (targetcore, SHARED) can actually be generated.
#
# WHAT IT DOES NOT PROVE -- and this is the important half
#   * NOTHING IS COMPILED OR LINKED. The stub targets below are empty INTERFACE
#     libraries. They carry no Msgcore headers and no import library, so the
#     generated project would fail at the first #include of P2PmsgBSTR.h. The
#     CI job deliberately stops after generate.
#   * It therefore says nothing about whether TargetCore compiles, links, or
#     works. It proves the build script is well-formed, and that is all.
#   * The Linux branch of the component script is NOT exercised: it compiles
#     ../Msgcore/Platform/p2piocp.cpp, which is in a sibling repository, and requires
#     liburing and OpenSSL via find_package/pkg_check_modules. A Linux
#     parse-check would fail on a missing source file for reasons that are not
#     defects. Only the WIN32 branch is covered here.
#   * A green result here must never be read as "the repo builds standalone".
#     It does not. See Readme.md "The sibling dependencies".
# ---------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.24)
project(TargetCoreParseCheck LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# STUBS. Real definitions live in ../Msgcore/CMakeLists.txt and
# ../Msgcore/Platform/CMakeLists.txt in the unpublished parent solution. Empty on
# purpose: this project must never be able to compile anything, so that nobody
# can mistake a green parse-check for a build.
add_library(msgcore INTERFACE)
add_library(p2pplatform INTERFACE)

# msgcore has to be in an INSTALLED EXPORT SET, or this project does not generate
# at all -- and it did not, from the day repo-invariants.yml was added until
# 2026-09-04. The component script links msgcore as a bare PUBLIC dependency,
# deliberately: Msgcore/CMakeLists.txt explains that the installed targetcore
# really does need the installed msgcore beside it to load, so unlike p2pplatform
# it must NOT be wrapped in $<BUILD_INTERFACE:>. install(TARGETS targetcore EXPORT
# TargetCoreTargets) then refuses at GENERATE time -- "requires target msgcore that
# is not in any export set" -- and a generate failure is not something the stub can
# opt out of. In the real parent solution msgcore is exported, by
# install(TARGETS msgcore EXPORT MsgcoreTargets). These two lines are that fact.
#
# BOTH are needed. install(TARGETS ... EXPORT) alone still fails: CMake wants the
# export set to be installed somewhere, not merely named. Nothing is installed by
# either -- the CI job stops after generate and never runs `cmake --install` -- so
# the destination below is a required argument pointing at a directory that will
# never exist, and the stub stays as inert as the rest of this file.
install(TARGETS msgcore EXPORT MsgcoreTargets)
install(EXPORT MsgcoreTargets DESTINATION lib/cmake/Msgcore)

# The component script under test. EXCLUDE_FROM_ALL so that even an accidental
# `cmake --build` does not try to compile it.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../.. targetcore-parse-check EXCLUDE_FROM_ALL)
