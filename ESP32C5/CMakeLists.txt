cmake_minimum_required(VERSION 3.5)

# Dodaj flagę linkera globalnie
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-zmuldefs")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(projectZero)
