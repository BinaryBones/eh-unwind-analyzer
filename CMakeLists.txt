cmake_minimum_required(VERSION 3.23)

project(
    eh_unwind_analyzer
    VERSION 1.0.0
    DESCRIPTION "Static and dynamic analyzer for Windows x64 EH/Unwind metadata"
    LANGUAGES C
)

include(CTest)

option(EHUA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(EHUA_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(EHUA_ENABLE_COVERAGE "Enable GCC/Clang coverage instrumentation" OFF)
option(EHUA_BUILD_FUZZER "Build the Clang libFuzzer parser harness" OFF)

if(EHUA_ENABLE_SANITIZERS AND EHUA_ENABLE_COVERAGE)
    message(FATAL_ERROR "Sanitizer and coverage instrumentation cannot be enabled together")
endif()

if(WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "EH/Unwind Analyzer supports Windows x64 builds only")
endif()

function(ehua_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS=1)
        if(EHUA_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(
            ${target}
            PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                -Wconversion
                -Wshadow
                -Wformat=2
        )
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${target} PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
        endif()
        if(EHUA_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

function(ehua_apply_instrumentation target)
    if(EHUA_ENABLE_SANITIZERS)
        if(MSVC)
            message(FATAL_ERROR "EHUA_ENABLE_SANITIZERS is currently supported with GCC or Clang")
        endif()
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    elseif(EHUA_ENABLE_COVERAGE)
        if(MSVC)
            message(FATAL_ERROR "EHUA_ENABLE_COVERAGE is currently supported with GCC or Clang")
        endif()
        target_compile_options(${target} PRIVATE --coverage -O0 -g)
        target_link_options(${target} PRIVATE --coverage)
    endif()
endfunction()

set(EHUA_CORE_SOURCES
    src/app_info.c
    src/dynamic_win.c
    src/heuristics.c
    src/pe.c
    src/report.c
    src/unwind.c
    src/util.c
)

add_library(ehua_core STATIC ${EHUA_CORE_SOURCES})
target_include_directories(
    ehua_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(ehua_core PUBLIC c_std_17)

if(WIN32)
    target_compile_definitions(ehua_core PUBLIC WIN32_LEAN_AND_MEAN=1)
endif()

if(MINGW)
    target_compile_definitions(ehua_core PUBLIC __USE_MINGW_ANSI_STDIO=1)
endif()
ehua_apply_warnings(ehua_core)

add_executable(eh_unwind_analyzer src/main.c)
target_link_libraries(eh_unwind_analyzer PRIVATE ehua_core)
ehua_apply_warnings(eh_unwind_analyzer)
ehua_apply_instrumentation(ehua_core)
ehua_apply_instrumentation(eh_unwind_analyzer)

if(EHUA_BUILD_FUZZER)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "EHUA_BUILD_FUZZER requires Clang")
    endif()
    include(CheckCSourceCompiles)
    set(EHUA_SAVED_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
    set(EHUA_SAVED_REQUIRED_LINK_OPTIONS "${CMAKE_REQUIRED_LINK_OPTIONS}")
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -fsanitize=fuzzer,address,undefined")
    set(CMAKE_REQUIRED_LINK_OPTIONS -fsanitize=fuzzer,address,undefined)
    check_c_source_compiles(
        "#include <stddef.h>
         #include <stdint.h>
         int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
             return (data != 0 && size != 0) ? 0 : 0;
         }"
        EHUA_LIBFUZZER_AVAILABLE
    )
    set(CMAKE_REQUIRED_FLAGS "${EHUA_SAVED_REQUIRED_FLAGS}")
    set(CMAKE_REQUIRED_LINK_OPTIONS "${EHUA_SAVED_REQUIRED_LINK_OPTIONS}")
    if(NOT EHUA_LIBFUZZER_AVAILABLE)
        message(FATAL_ERROR
            "Clang is present, but its libFuzzer runtime is unavailable. "
            "Install a full LLVM/Clang toolchain or leave EHUA_BUILD_FUZZER=OFF.")
    endif()
    add_executable(
        ehua_parser_fuzzer
        tests/fuzz/fuzz_parser.c
        src/heuristics.c
        src/pe.c
        src/unwind.c
        src/util.c
    )
    target_include_directories(ehua_parser_fuzzer PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_compile_features(ehua_parser_fuzzer PRIVATE c_std_17)
    ehua_apply_warnings(ehua_parser_fuzzer)
    target_compile_options(
        ehua_parser_fuzzer
        PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
    )
    target_link_options(ehua_parser_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

if(BUILD_TESTING)
    function(ehua_add_unit_test target source)
        add_executable(${target} ${source})
        target_link_libraries(${target} PRIVATE ehua_core)
        if(MSVC)
            target_compile_options(${target} PRIVATE /UNDEBUG)
        else()
            target_compile_options(${target} PRIVATE -UNDEBUG)
        endif()
        ehua_apply_warnings(${target})
        ehua_apply_instrumentation(${target})
        set(unit_workdir "${CMAKE_CURRENT_BINARY_DIR}/tests/unit/${target}")
        file(MAKE_DIRECTORY "${unit_workdir}")
        add_test(NAME ${target} COMMAND ${target})
        set_tests_properties(
            ${target}
            PROPERTIES
                WORKING_DIRECTORY "${unit_workdir}"
                TIMEOUT 30
        )
    endfunction()

    ehua_add_unit_test(unit_unwind tests/unit/unit_unwind.c)
    ehua_add_unit_test(unit_heuristics tests/unit/unit_heuristics.c)
    ehua_add_unit_test(unit_heuristics_mitigations tests/unit/unit_heuristics_mitigations.c)
    ehua_add_unit_test(unit_heuristics_context tests/unit/unit_heuristics_context.c)
    ehua_add_unit_test(unit_heuristics_combos tests/unit/unit_heuristics_combos.c)
    ehua_add_unit_test(unit_core_edges tests/unit/unit_core_edges.c)
    ehua_add_unit_test(unit_report_json tests/unit/unit_report_json.c)
    ehua_add_unit_test(unit_report_html tests/unit/unit_report_html.c)
    ehua_add_unit_test(unit_matrix_report tests/unit/unit_matrix_report.c)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME regression_samples
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_regression_samples.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
        )
        set_tests_properties(regression_samples PROPERTIES TIMEOUT 120)
        add_test(
            NAME dynamic_validator
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_dynamic_validator.py"
        )
        set_tests_properties(dynamic_validator PROPERTIES TIMEOUT 30)
        add_test(
            NAME report_semantics
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_report_semantics.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
        )
        set_tests_properties(report_semantics PROPERTIES TIMEOUT 30)
        add_test(
            NAME generated_report_quality
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_generated_report_quality.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
        )
        set_tests_properties(generated_report_quality PROPERTIES TIMEOUT 30)
        add_test(
            NAME release_metadata
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_release_metadata.py"
        )
        set_tests_properties(release_metadata PROPERTIES TIMEOUT 30)
        add_test(
            NAME release_hygiene
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_release_hygiene.py"
        )
        set_tests_properties(release_hygiene PROPERTIES TIMEOUT 30)
        add_test(
            NAME cli_contract
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_contract.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
        )
        set_tests_properties(cli_contract PROPERTIES TIMEOUT 60)
        add_test(
            NAME unsupported_architecture
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_unsupported_architecture.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
        )
        set_tests_properties(unsupported_architecture PROPERTIES TIMEOUT 30)
        add_test(
            NAME input_validation_reports
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_input_validation_reports.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
        )
        set_tests_properties(input_validation_reports PROPERTIES TIMEOUT 60)
        add_test(
            NAME mutation_fuzz
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_mutation_fuzz.py"
                "$<TARGET_FILE:eh_unwind_analyzer>"
                --cases
                120
        )
        set_tests_properties(
            mutation_fuzz
            PROPERTIES
                TIMEOUT 180
                LABELS "fuzz"
        )
        set(EHUA_PYTHON_TEST_ENV
            "PYTHONDONTWRITEBYTECODE=1"
            "PYTHONPATH=${CMAKE_BINARY_DIR}/pydeps"
        )
        set_tests_properties(
            regression_samples
            dynamic_validator
            report_semantics
            generated_report_quality
            release_metadata
            release_hygiene
            cli_contract
            unsupported_architecture
            input_validation_reports
            mutation_fuzz
            PROPERTIES
                ENVIRONMENT "${EHUA_PYTHON_TEST_ENV}"
        )
    endif()
endif()

install(TARGETS eh_unwind_analyzer RUNTIME DESTINATION bin)
install(
    DIRECTORY docs/
    DESTINATION share/eh_unwind_analyzer/docs
    PATTERN ".DS_Store" EXCLUDE
    PATTERN "._*" EXCLUDE
    PATTERN "__pycache__" EXCLUDE
    PATTERN "*.pyc" EXCLUDE
)
install(
    DIRECTORY ghidra/
    DESTINATION share/eh_unwind_analyzer/ghidra
    PATTERN ".DS_Store" EXCLUDE
    PATTERN "._*" EXCLUDE
    PATTERN "__pycache__" EXCLUDE
    PATTERN "*.pyc" EXCLUDE
)
install(
    DIRECTORY examples/
    DESTINATION share/eh_unwind_analyzer/examples
    PATTERN ".DS_Store" EXCLUDE
    PATTERN "._*" EXCLUDE
)
install(
    FILES
        README.md
        LICENSE
        CHANGELOG.md
        SECURITY.md
        CONTRIBUTING.md
    DESTINATION share/eh_unwind_analyzer
)

set(CPACK_PACKAGE_NAME "EH-Unwind-Analyzer")
set(CPACK_PACKAGE_VENDOR "EH/Unwind Analyzer project")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_FILE_NAME "eh-unwind-analyzer-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_GENERATOR "ZIP")
include(CPack)
