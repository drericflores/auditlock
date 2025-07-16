# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name
project(LockAudit LANGUAGES CXX)

# Find Qt5 packages required for the project
# 'Widgets' is needed for graphical UI components
# 'Core' is implicitly included with Widgets
find_package(Qt5 COMPONENTS Widgets REQUIRED)

# --- ADD THIS LINE ---
# Enable automatic MOC (Meta-Object Compiler) processing for Qt classes
set(CMAKE_AUTOMOC ON)
# ---------------------

# Add source files
set(SOURCES
    main.cpp
    MainWindow.cpp
    SecurityScanner.cpp
)

# Add header files (CMake automatically finds them if they're in the same directory as sources or specified include dirs)
set(HEADERS
    MainWindow.h
    SecurityScanner.h
)

# Add the executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link with Qt5 libraries
target_link_libraries(${PROJECT_NAME} PRIVATE Qt5::Widgets)

# If you want to install it system-wide later (optional)
# install(TARGETS ${PROJECT_NAME} DESTINATION bin)