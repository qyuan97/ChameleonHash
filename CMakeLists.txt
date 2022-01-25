cmake_minimum_required(VERSION 3.14)
project(ChameleonHash)

set(CMAKE_CXX_STANDARD 20)
set(INC_DIR /usr/local/include)
set(LINK_DIR /usr/local/lib)

include_directories(${INC_DIR})
link_directories(${LINK_DIR})

add_executable(ch chameleonhash.cpp)
target_link_libraries(ch cryptopp)