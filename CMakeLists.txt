cmake_minimum_required(VERSION 3.20)

project(DiscordMiniBypass)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(WINDIVERT_INCLUDE ${CMAKE_SOURCE_DIR}/third_party/windivert/include/windivert.h)
set(WINDIVERT_LIB ${CMAKE_SOURCE_DIR}/third_party/windivert/lib/WinDivert.lib)
set(WINDIVERT_DLL ${CMAKE_SOURCE_DIR}/third_party/windivert/bin/WinDivert.dll)
set(WINDIVERT_DRIVER ${CMAKE_SOURCE_DIR}/third_party/windivert/bin/WinDivert64.sys)

foreach(REQUIRED_FILE
    ${WINDIVERT_INCLUDE}
    ${WINDIVERT_LIB}
    ${WINDIVERT_DLL}
    ${WINDIVERT_DRIVER}
)
    if(NOT EXISTS ${REQUIRED_FILE})
        message(FATAL_ERROR "Missing ${REQUIRED_FILE}. Download WinDivert x64 from https://github.com/basil00/WinDivert/releases")
    endif()
endforeach()

add_executable(DiscordMiniBypass
    src/main.cpp
    resources/app.rc
)

target_include_directories(DiscordMiniBypass PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/windivert/include
)

target_link_libraries(DiscordMiniBypass PRIVATE
    ${WINDIVERT_LIB}
    Ws2_32
)

add_custom_command(TARGET DiscordMiniBypass POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${WINDIVERT_DLL}
        $<TARGET_FILE_DIR:DiscordMiniBypass>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${WINDIVERT_DRIVER}
        $<TARGET_FILE_DIR:DiscordMiniBypass>
)
