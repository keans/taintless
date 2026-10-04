cmake_minimum_required(VERSION 3.20)
find_package(OpenSSL REQUIRED)
find_package(Threads)
target_link_libraries(app PRIVATE OpenSSL::Crypto Threads::Threads)
