cmake_minimum_required(VERSION 3.14)
project(OhttpGP)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
# Hide BoringSSL symbols.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")

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
set(BORINGSSL_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    boringssl
    GIT_REPOSITORY https://github.com/google/boringssl.git
    GIT_TAG e4978786daee58f51dcb98bc9665883d6f8567c0
)
FetchContent_MakeAvailable(boringssl)

# Add the main library (ohttp)
add_library(ohttp ohttp.cc)
target_link_libraries(ohttp PRIVATE ${BoringSSL_BINARY_DIR}/libcrypto.a ${BoringSSL_BINARY_DIR}/libssl.a)
target_include_directories(ohttp PRIVATE ${boringssl_SOURCE_DIR}/include)

# Add the test executable
add_executable(ohttp_test ohttp_test.cc)

# Link Google Test and the main library (ohttp) to the test executable
target_link_libraries(ohttp_test PRIVATE gtest gtest_main ohttp)

# Enable testing
enable_testing()

# Add tests
add_test(NAME ohttp_test COMMAND ohttp_test)