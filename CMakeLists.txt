cmake_minimum_required(VERSION 3.24)
project(dayz_server_nobe LANGUAGES C CXX)

include(FetchContent)

set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)

FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(zydis)

add_executable(dayz_server_nobe main.cxx)
target_compile_features(dayz_server_nobe PRIVATE cxx_std_23)
target_link_libraries(dayz_server_nobe PRIVATE Zydis)
