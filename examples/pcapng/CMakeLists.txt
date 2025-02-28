
set(CMAKE_CXX_STANDARD 17)
add_executable(ics-mka-pcapng main.cpp)
target_link_libraries(ics-mka-pcapng PUBLIC ics-mka)