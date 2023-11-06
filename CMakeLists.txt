cmake_minimum_required(VERSION 3.14)

project(openssl_symetric_encription LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

find_package(OpenSSL REQUIRED)

add_executable(openssl_symetric_encription
  main.cpp
  CMakeLists.txt symetric_encyprtion.cpp symetric_encyprtion.h
)
target_link_libraries(openssl_symetric_encription Qt${QT_VERSION_MAJOR}::Core)

include(GNUInstallDirs)
install(TARGETS openssl_symetric_encription
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)


