cmake_minimum_required(VERSION 3.16)
project(eternal_blue
    VERSION 0.1.0
    DESCRIPTION "Eternal-Blue C++ Messaging Client"
    LANGUAGES CXX
)

# ---language---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ---dependencies---
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

include(FetchContent)
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json
    GIT_TAG v3.11.3)
FetchContent_MakeAvailable(json)

FetchContent_Declare(doctest
    GIT_REPOSITORY https://github.com/doctest/doctest
    GIT_TAG v2.4.11
)
FetchContent_MakeAvailable(doctest)

# --- core object library (shared between main and tests) ---

add_library(eternal-blue-core OBJECT
    src/TlsConnection.cpp
    src/HttpClient.cpp
    src/CryptoContext.cpp
    src/Base64.cpp
    src/Keystore.cpp
    src/TrustStore.cpp 
    src/LocalStore.cpp 
    src/User.cpp 
    src/Message.cpp
    src/Client.cpp
)

target_include_directories(eternal-blue-core PUBLIC include)

target_link_libraries(eternal-blue-core PUBLIC
    OpenSSL::SSL 
    OpenSSL::Crypto 
    SQLite::SQLite3 
    PkgConfig::SODIUM 
    nlohmann_json::nlohmann_json
)

# --- main executable ---
add_executable(eternal-blue src/main.cpp)
target_link_libraries(eternal-blue PRIVATE eternal-blue-core)


# --- tests ---

enable_testing()
add_executable(eternal-blue-tests
    tests/crypto_test.cpp
    tests/tls_test.cpp
    tests/store_test.cpp
)
target_link_libraries(eternal-blue-tests PRIVATE
    eternal-blue-core
    doctest::doctest
)
add_test(NAME unit_tests COMMAND eternal-blue-tests)