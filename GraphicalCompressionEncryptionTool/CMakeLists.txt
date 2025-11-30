cmake_minimum_required(VERSION 3.16)
project(GraphicalCompressionEncryptionTool)

# 强制在Linux系统编译
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project can only be compiled on Linux systems")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 强制设置为Release构建类型
set(CMAKE_BUILD_TYPE Release)

# 设置可执行文件输出目录为build/bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 查找必要的包
find_package(PkgConfig REQUIRED)

# 查找 GTKMM 4.0
pkg_check_modules(GTKMM REQUIRED gtkmm-4.0)

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

# 设置包含目录
include_directories(${GTKMM_INCLUDE_DIRS} include /usr/local/include)
include_directories(${OPENSSL_INCLUDE_DIR})

# 检查编译器对C++17文件系统的支持
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++17" HAS_STD_CXX17)
if(NOT HAS_STD_CXX17)
    message(FATAL_ERROR "Compiler does not support C++17")
endif()

# 设置编译器特定优化和警告选项
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # 通用警告选项
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    
    # 额外的警告选项
    add_compile_options(-Wduplicated-cond -Wduplicated-branches -Wlogical-op)
    add_compile_options(-Wnull-dereference -Wuseless-cast -Wdouble-promotion)
    add_compile_options(-Wformat=2 -Wimplicit-fallthrough=5)
    
    # 最高级别优化（强制Release模式）
    add_compile_options(-O3 -march=native -mtune=native)
    add_compile_options(-ffunction-sections -fdata-sections)
    add_compile_options(-DNDEBUG)
    
    # 链接时优化
    add_compile_options(-flto)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    
    # 额外的发布版优化
    add_compile_options(-fno-plt -fno-semantic-interposition)
    
    # 只静态链接C++标准库，不静态链接其他库
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

# 添加GTKMM的编译选项
add_compile_options(${GTKMM_CFLAGS_OTHER})

# 设置链接目录
link_directories(${GTKMM_LIBRARY_DIRS} /usr/local/lib)

# 添加可执行文件
add_executable(GraphicalCompressionEncryptionTool
    src/main.cpp
    src/backgroundprocessing.cpp
)

# 设置目标属性
set_target_properties(GraphicalCompressionEncryptionTool PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# 强制查找iconv静态库 - 必须在/usr/local/lib/
# 下载地址https://www.gnu.org/software/libiconv/
find_library(ICONV_STATIC_LIB 
    NAMES libiconv.a 
    PATHS /usr/local/lib
    NO_DEFAULT_PATH
    REQUIRED
)

find_library(CHARSET_STATIC_LIB 
    NAMES libcharset.a 
    PATHS /usr/local/lib
    NO_DEFAULT_PATH
)

# 检查文件系统库支持
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC 需要链接 libstdc++fs
    target_link_libraries(GraphicalCompressionEncryptionTool stdc++fs)
    message(STATUS "Using libstdc++fs for filesystem support")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Clang 通常不需要额外链接
    message(STATUS "Using built-in filesystem support for Clang")
endif()

# 链接动态库（GTKMM、OpenSSL等）
target_link_libraries(GraphicalCompressionEncryptionTool
    ${GTKMM_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    ${CMAKE_DL_LIBS}
)

# 强制静态链接iconv库
target_link_libraries(GraphicalCompressionEncryptionTool ${ICONV_STATIC_LIB})
message(STATUS "ICONV static library: ${ICONV_STATIC_LIB}")

if(CHARSET_STATIC_LIB)
    target_link_libraries(GraphicalCompressionEncryptionTool ${CHARSET_STATIC_LIB})
    message(STATUS "CHARSET static library: ${CHARSET_STATIC_LIB}")
else()
    message(WARNING "CHARSET static library not found, continuing without it")
endif()

# 显示构建配置信息
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version: ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Executable output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "Optimization: Maximum (-O3) with LTO")
message(STATUS "Static linking: libgcc, libstdc++, and iconv only")
message(STATUS "Dynamic linking: GTKMM, OpenSSL, and system libraries")
message(STATUS "Platform: Linux only")

# 检查必要的库
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

if(GTKMM_FOUND)
    message(STATUS "GTKMM 4.0 found")
else()
    message(FATAL_ERROR "GTKMM 4.0 not found")
endif()

# 最终验证
if(NOT ICONV_STATIC_LIB)
    message(FATAL_ERROR "ICONV static library not found in /usr/local/lib/")
endif()

message(STATUS "Build configuration completed successfully!")