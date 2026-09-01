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
# run_install_check.cmake -- the p2p_installtree gate.  Stage 5 step 14,
# exit criterion: "cmake --install output is copied and a
# program links and runs against it.  Falsify by deleting the staged siblings
# and watching the load fail."
#
# Four phases, and phase 4 is the one that makes the other three mean anything:
#
#   1  INSTALL   -- cmake --install into a scratch prefix, from nothing but the
#                   build tree, and check the manifest by name.
#   2  BUILD     -- configure a project that has never heard of this source tree
#                   and knows only find_package(TargetCore).
#   3  RUN       -- run it, with the build tree scrubbed off PATH.
#   4  FALSIFY   -- take the sibling runtime out of the prefix and run THE SAME
#                   BINARY again.  It must fail to load.
#
# Phase 4 is not decoration.  Without it a green phase 3 proves only that the
# program found A copy of the libraries somewhere -- and on Windows the test
# preset puts the build tree's Msgcore and TargetCore directories on PATH for
# every ctest process, so "somewhere" would very likely have been the build
# tree, and an install prefix containing nothing but a header could have passed.
# Scrubbing PATH in phase 3 and deleting the sibling in phase 4 are two halves
# of the same argument: the first removes the other copy, the second proves the
# program was really using the one that is left.
#
# Invoked as:  cmake -DBUILD_DIR=... -DSOURCE_DIR=... -DWORK_DIR=...
#                    -DCONFIG=... -DGENERATOR=... -DPLATFORM=... -DTOOLSET=...
#                    -P run_install_check.cmake

cmake_minimum_required(VERSION 3.24)

foreach(_req BUILD_DIR SOURCE_DIR WORK_DIR)
    if(NOT DEFINED ${_req} OR "${${_req}}" STREQUAL "")
        message(FATAL_ERROR "run_install_check: -D${_req} is required")
    endif()
endforeach()

set(STAGE    "${WORK_DIR}/stage")
set(CONSUMER "${WORK_DIR}/consumer")

function(banner text)
    message(STATUS "")
    message(STATUS "======== ${text}")
endfunction()

# Run a command and stop the whole gate if it fails, naming the phase.
function(run_or_die what)
    execute_process(COMMAND ${ARGN}
                    RESULT_VARIABLE _rc
                    OUTPUT_VARIABLE _out
                    ERROR_VARIABLE  _err)
    if(NOT _rc EQUAL 0)
        message("${_out}")
        message("${_err}")
        message(FATAL_ERROR "INSTALL TREE GATE FAILED: ${what} (exit ${_rc})")
    endif()
    message("${_out}")
endfunction()

# ---------------------------------------------------------------------------
# Phase 1 -- INSTALL
# ---------------------------------------------------------------------------
banner("1/4 INSTALL  ->  ${STAGE}")

# A stale prefix would let a file deleted from the install rules keep passing
# the manifest check for ever, so the prefix is destroyed first, every run.
file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${STAGE}")
file(MAKE_DIRECTORY "${CONSUMER}")

set(_install_args --install "${BUILD_DIR}" --prefix "${STAGE}")
if(NOT "${CONFIG}" STREQUAL "")
    list(APPEND _install_args --config "${CONFIG}")
endif()
run_or_die("cmake --install" ${CMAKE_COMMAND} ${_install_args})

# What must be there, by file name.  Names rather than full paths because
# CMAKE_INSTALL_LIBDIR is lib on Debian and lib64 on Fedora, and a gate that
# hardcoded one would be a gate that only works on the machine it was written
# on.  Matching is case-insensitive: the CMake target is `targetcore` while the
# vcxproj-built DLL is `TargetCore.dll`, and on Windows those are one file.
if(WIN32)
    set(_want targetcore.dll msgcore.dll targetcore.lib msgcore.lib)
else()
    set(_want libtargetcore.so libmsgcore.so)
endif()
list(APPEND _want
     # Headers.  BOTH version headers are listed by name because their absence
     # is exactly the defect step 14 found: TargetCore_c.h was staged without
     # TargetCore_version.h, which it includes on its first line, so the shipped
     # header did not preprocess and nothing said so.
     targetcore_c.h targetcore_version.h
     msgcore_c.h    msgcore_version.h
     # Apache-2.0 section 4.  Two components, two NOTICE files, and they are
     # different files -- so both must survive, in their own directories.
     license notice
     # The config packages.
     targetcoreconfig.cmake targetcoreconfigversion.cmake targetcoretargets.cmake
     msgcoreconfig.cmake    msgcoreconfigversion.cmake    msgcoretargets.cmake)

file(GLOB_RECURSE _staged RELATIVE "${STAGE}" "${STAGE}/*")
message(STATUS "staged ${STAGE}:")
foreach(_f IN LISTS _staged)
    message(STATUS "    ${_f}")
endforeach()

string(TOLOWER "${_staged}" _staged_lc)
set(_missing "")
foreach(_w IN LISTS _want)
    set(_hit OFF)
    foreach(_f IN LISTS _staged_lc)
        get_filename_component(_base "${_f}" NAME)
        if(_base STREQUAL _w)
            set(_hit ON)
            break()
        endif()
    endforeach()
    if(NOT _hit)
        list(APPEND _missing "${_w}")
    endif()
endforeach()
if(_missing)
    message(FATAL_ERROR
            "INSTALL TREE GATE FAILED: the install prefix is incomplete.\n"
            "  missing: ${_missing}\n"
            "  This is a staging defect, not a build failure -- the library "
            "built and the install rules did not put all of it in the prefix.")
endif()

# The two NOTICE files must be DIFFERENT files in DIFFERENT directories.  One
# install(FILES) destination shared between the components would have silently
# left whichever ran second, and the attribution of the other would be gone
# with nothing to show for it.
set(_notices "")
foreach(_f IN LISTS _staged)
    get_filename_component(_base "${_f}" NAME)
    if(_base STREQUAL "NOTICE")
        list(APPEND _notices "${_f}")
    endif()
endforeach()
list(LENGTH _notices _n_notices)
if(_n_notices LESS 2)
    message(FATAL_ERROR
            "INSTALL TREE GATE FAILED: ${_n_notices} NOTICE file(s) staged, "
            "expected one per component. Attribution for at least one "
            "component is missing from the artifact (Apache-2.0 section 4).")
endif()

# ---------------------------------------------------------------------------
# Phase 2 -- BUILD the stranger
# ---------------------------------------------------------------------------
banner("2/4 BUILD    ->  ${CONSUMER}")

set(_cfg_args -S "${SOURCE_DIR}" -B "${CONSUMER}"
              "-DCMAKE_PREFIX_PATH=${STAGE}")
if(NOT "${GENERATOR}" STREQUAL "")
    list(APPEND _cfg_args -G "${GENERATOR}")
endif()
if(NOT "${PLATFORM}" STREQUAL "")
    list(APPEND _cfg_args -A "${PLATFORM}")
endif()
if(NOT "${TOOLSET}" STREQUAL "")
    list(APPEND _cfg_args -T "${TOOLSET}")
endif()
if(NOT "${CONFIG}" STREQUAL "")
    # Harmless on a multi-config generator, required on a single-config one --
    # and the consumer must be built in the SAME configuration as the libraries
    # it links, or on Windows it pairs a release CRT with debug DLLs.
    list(APPEND _cfg_args "-DCMAKE_BUILD_TYPE=${CONFIG}")
endif()
run_or_die("consumer configure" ${CMAKE_COMMAND} ${_cfg_args})

set(_build_args --build "${CONSUMER}")
if(NOT "${CONFIG}" STREQUAL "")
    list(APPEND _build_args --config "${CONFIG}")
endif()
run_or_die("consumer build" ${CMAKE_COMMAND} ${_build_args})

if(WIN32)
    file(GLOB_RECURSE _exe "${CONSUMER}/installed_consumer.exe")
else()
    file(GLOB_RECURSE _exe "${CONSUMER}/installed_consumer")
endif()
if(NOT _exe)
    message(FATAL_ERROR "INSTALL TREE GATE FAILED: consumer built but no executable found")
endif()
list(GET _exe 0 EXE)
message(STATUS "consumer: ${EXE}")

# ---------------------------------------------------------------------------
# Phase 3 -- RUN, with the build tree scrubbed off the search path
# ---------------------------------------------------------------------------
banner("3/4 RUN")

# Every PATH entry that lies inside the build tree comes out.  If one were left
# in, Windows would load the build tree's DLLs and this gate would pass with an
# empty install prefix -- which is the precise failure it exists to detect.
file(TO_CMAKE_PATH "$ENV{PATH}" _path_in)
string(TOLOWER "${BUILD_DIR}" _bd_lc)
set(_path_out "")
foreach(_p IN LISTS _path_in)
    string(TOLOWER "${_p}" _p_lc)
    string(FIND "${_p_lc}" "${_bd_lc}" _at)
    if(_at EQUAL -1)
        list(APPEND _path_out "${_p}")
    else()
        message(STATUS "scrubbed from PATH: ${_p}")
    endif()
endforeach()

if(WIN32)
    set(_stage_runtime "${STAGE}/bin")
    set(_sep ";")
else()
    file(GLOB _libdirs "${STAGE}/lib" "${STAGE}/lib64")
    if(NOT _libdirs)
        message(FATAL_ERROR "INSTALL TREE GATE FAILED: no lib/ or lib64/ in ${STAGE}")
    endif()
    list(GET _libdirs 0 _stage_runtime)
    set(_sep ":")
endif()
set(_path_final "${_stage_runtime}")
foreach(_p IN LISTS _path_out)
    file(TO_NATIVE_PATH "${_p}" _pn)
    string(APPEND _path_final "${_sep}${_pn}")
endforeach()
file(TO_NATIVE_PATH "${_stage_runtime}" _stage_runtime_native)

# A function rather than two copies, because phase 4 must run the binary the
# EXACT same way phase 3 did.  If the two runs differed in environment, a
# phase-4 failure would not be evidence about the missing sibling.
function(run_consumer out_rc out_text)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env
                "PATH=${_path_final}"
                "LD_LIBRARY_PATH=${_stage_runtime_native}"
                "${EXE}"
        RESULT_VARIABLE _rc
        OUTPUT_VARIABLE _out
        ERROR_VARIABLE  _err)
    set(${out_rc}   "${_rc}"          PARENT_SCOPE)
    set(${out_text} "${_out}${_err}"  PARENT_SCOPE)
endfunction()

run_consumer(_rc _text)
message("${_text}")
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
            "INSTALL TREE GATE FAILED: the consumer did not run against the "
            "install prefix (exit ${_rc}).")
endif()
if(NOT _text MATCHES "INSTALL TREE CONSUMER OK")
    message(FATAL_ERROR
            "INSTALL TREE GATE FAILED: the consumer exited 0 without printing "
            "its success marker. Exit status alone is not evidence here -- a "
            "loader failure can still be a zero exit on some shells.")
endif()

# ---------------------------------------------------------------------------
# Phase 4 -- FALSIFY: delete the staged sibling, watch the load fail
# ---------------------------------------------------------------------------
banner("4/4 FALSIFY  (remove the staged Msgcore runtime)")

set(_siblings "")
foreach(_f IN LISTS _staged)
    get_filename_component(_base "${_f}" NAME)
    string(TOLOWER "${_base}" _base_lc)
    if(_base_lc STREQUAL "msgcore.dll" OR _base_lc STREQUAL "libmsgcore.so")
        list(APPEND _siblings "${STAGE}/${_f}")
    endif()
endforeach()
if(NOT _siblings)
    message(FATAL_ERROR
            "INSTALL TREE GATE FAILED: no staged Msgcore runtime to remove. "
            "Phase 1 should already have caught this.")
endif()

foreach(_s IN LISTS _siblings)
    message(STATUS "removing ${_s}")
    file(REMOVE "${_s}")
endforeach()

run_consumer(_rc2 _text2)
message("${_text2}")
if(_rc2 EQUAL 0)
    message(FATAL_ERROR
            "INSTALL TREE GATE FAILED: THE FALSIFICATION DID NOT FALSIFY.\n"
            "  The consumer still ran after the staged Msgcore runtime was "
            "deleted, which means it is NOT loading the library out of the "
            "install prefix. Some other copy is satisfying it -- the build "
            "tree, a system directory, or a stale file beside the executable. "
            "Phase 3 therefore proved nothing about the install tree.")
endif()
message(STATUS "the consumer failed to load without its sibling, as it must (exit ${_rc2})")

banner("INSTALL TREE GATE PASSED")
