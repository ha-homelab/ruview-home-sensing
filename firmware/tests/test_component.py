#!/usr/bin/env python3
"""Check the real WASM3 component in ESP-IDF-like CMake script mode."""

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("wasm3", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        component = root / "components/wasm3"
        component.mkdir(parents=True)
        shutil.copy(args.source / "components/wasm3/CMakeLists.txt", component)
        (root / "main").mkdir()
        shutil.copy(args.source / "main/CMakeLists.txt", root / "main")
        subprocess.run(
            ["git", "apply", str(ROOT / "patches/0004-pinned-wasm3-component.patch")],
            cwd=root,
            check=True,
        )
        (component / "wasm3-src").symlink_to(
            args.wasm3.resolve(), target_is_directory=True
        )
        build = root / "unrelated-build-directory"
        build.mkdir()
        script = build / "requirements.cmake"
        script.write_text(
            """cmake_minimum_required(VERSION 3.16)
function(idf_component_register)
  if(NOT ARGN MATCHES "wasm3-src/source/m3_compile.c")
    message(FATAL_ERROR "Real WASM3 sources must be registered")
  endif()
endfunction()
function(target_compile_definitions)
endfunction()
function(target_compile_options)
endfunction()
set(COMPONENT_LIB host-check)
"""
            + f'include("{component / "CMakeLists.txt"}")\n'
        )
        subprocess.run(["cmake", "-P", str(script)], cwd=build, check=True)
        main_script = build / "main-requirements.cmake"
        main_script.write_text(
            """cmake_minimum_required(VERSION 3.16)
function(idf_component_register)
  cmake_parse_arguments(MAIN "" "" "SRCS;INCLUDE_DIRS;REQUIRES" ${ARGN})
  if(NOT "wasm3" IN_LIST MAIN_REQUIRES)
    message(FATAL_ERROR "Main must require WASM3 before CONFIG_* is available")
  endif()
endfunction()
set(IDF_TARGET esp32s3)
"""
            + f'include("{root / "main/CMakeLists.txt"}")\n'
        )
        subprocess.run(["cmake", "-P", str(main_script)], cwd=build, check=True)
        (component / "wasm3-src").unlink()
        missing = subprocess.run(
            ["cmake", "-P", str(script)], cwd=build, capture_output=True, text=True
        )
        assert missing.returncode != 0 and "refusing a stub runtime" in missing.stderr
        print("CMake script-mode source lookup and missing-runtime rejection passed.")


if __name__ == "__main__":
    main()
