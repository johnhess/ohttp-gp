cmake_minimum_required(VERSION 3.14)
project(OhttpGP)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)

# Include FetchContent module
include(FetchContent)

# Fetch Google Test
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# Fetch BoringSSL from GitHub
FetchContent_Declare(
    boringssl
    GIT_REPOSITORY https://github.com/google/boringssl.git
    GIT_TAG e4978786daee58f51dcb98bc9665883d6f8567c0
)
FetchContent_MakeAvailable(boringssl)

# Add the main library (ohttp)
add_library(ohttp ohttp.cc)
target_link_libraries(ohttp PRIVATE crypto)

# Add the test executable
add_executable(ohttp_test ohttp_test.cc)

# Link Google Test and the main library (ohttp) to the test executable
target_link_libraries(ohttp_test PRIVATE gtest gtest_main ohttp)

# Enable testing
enable_testing()

# Add tests
add_test(NAME ohttp_test COMMAND ohttp_test)