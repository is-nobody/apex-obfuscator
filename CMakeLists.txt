# CMakeLists.txt
# Implementation of CMakeLists for Apex Obfuscator
# https://github.com/is-nobody/apex-obfuscator
# MIT license

cmake_minimum_required(VERSION 3.13)
project(Apex-Obfuscator VERSION 26.08 LANGUAGES C)

# enables gnu extensions 
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# all source files grouped by module
set(SOURCES
    main.c
    source/core/cipher.c
    source/core/cipher_ops.c
    source/core/encrypt_decrypt.c
    source/core/round_ops.c
    source/core/sbox.c
    source/core/keygen.c
    source/core/hash.c
    source/core/hmac.c
    source/core/kdf.c
    source/core/crypto_context.c
    source/cli/args.c
    source/utils/utils.c
)

add_executable(apex-obfuscator ${SOURCES})

# header search paths for include from any directory
target_include_directories(apex-obfuscator PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/core
    ${CMAKE_CURRENT_SOURCE_DIR}/source/cli
    ${CMAKE_CURRENT_SOURCE_DIR}/source/utils
)

# baseline warnings and posix compatibility
set(BASE_FLAGS 
    -Wall -Wextra
    -D_DEFAULT_SOURCE
)

# performance flags for gcc/clang (linux/macos/mingw)
set(HIGH_PERF_FLAGS
    -O3
    -flto
)

# native cpu flags only when NOT cross-compiling
if(NOT CMAKE_CROSSCOMPILING)
    list(APPEND HIGH_PERF_FLAGS -march=native -mtune=native)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(apex-obfuscator PRIVATE ${BASE_FLAGS} ${HIGH_PERF_FLAGS})
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(apex-obfuscator PRIVATE -flto)
    endif()
else()
    target_compile_options(apex-obfuscator PRIVATE ${BASE_FLAGS} -O2)
endif()

# strips debug symbols in release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET apex-obfuscator POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:apex-obfuscator>
        COMMENT "Stripping debug symbols..."
    )
endif()

# link bcrypt for bcryptgenrandom on windows
if(WIN32)
    target_link_libraries(apex-obfuscator PRIVATE bcrypt)
endif()

#[[
# standard build command
cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Release
cmake --build build/ --parallel
]]