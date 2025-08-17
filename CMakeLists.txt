cmake_minimum_required(VERSION 3.14)
project(ssh-proxy-core VERSION 1.0.0 LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set default build type to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Debug/Release specific flags
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/ssh_proxy.c
)

# Create library
add_library(ssh_proxy_lib ${SOURCES})

# Main executable
add_executable(ssh-proxy-core src/main.c)
target_link_libraries(ssh-proxy-core ssh_proxy_lib)

# Find required packages for testing
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTEST REQUIRED gtest)
pkg_check_modules(GTEST_MAIN REQUIRED gtest_main)

# Enable testing
enable_testing()

# Test executable
add_executable(test_runner tests/test_ssh_proxy.cpp)
target_link_libraries(test_runner 
    ssh_proxy_lib 
    ${GTEST_LIBRARIES} 
    ${GTEST_MAIN_LIBRARIES}
    pthread
)

target_include_directories(test_runner PRIVATE 
    ${GTEST_INCLUDE_DIRS}
)

target_compile_options(test_runner PRIVATE 
    ${GTEST_CFLAGS_OTHER}
)

# Add test
add_test(NAME ssh_proxy_tests COMMAND test_runner)

# Custom targets for convenience
add_custom_target(run
    COMMAND ssh-proxy-core
    DEPENDS ssh-proxy-core
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running ssh-proxy-core"
)

# Install target
install(TARGETS ssh-proxy-core
    RUNTIME DESTINATION bin
)

# Package configuration
set(CPACK_PACKAGE_NAME "ssh-proxy-core")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SSH Proxy Core Library")
set(CPACK_PACKAGE_VENDOR "Your Organization")
set(CPACK_GENERATOR "TGZ;DEB")
include(CPack)
