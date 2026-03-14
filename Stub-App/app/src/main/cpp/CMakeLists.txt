cmake_minimum_required(VERSION 3.18.1)

project("guard" LANGUAGES CXX)

add_library(guard SHARED
    guard.cpp
    anti_debug.cpp
)

target_compile_options(guard PRIVATE
    -std=c++17
    -Wall -Wextra
    -fvisibility=hidden          # 仅导出 JNI_OnLoad，隐藏内部符号
    -ffunction-sections
    -fdata-sections
)

target_link_options(guard PRIVATE
    -Wl,--gc-sections            # 移除未使用段
)

find_library(log-lib log)

target_link_libraries(guard
    ${log-lib}
)
