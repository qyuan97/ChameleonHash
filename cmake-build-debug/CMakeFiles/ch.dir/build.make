# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/qy/Desktop/CLion/clion-2021.3.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/qy/Desktop/CLion/clion-2021.3.2/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/qy/Documents/ChameleonHash

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/qy/Documents/ChameleonHash/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ch.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/ch.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/ch.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ch.dir/flags.make

CMakeFiles/ch.dir/chameleonhash.cpp.o: CMakeFiles/ch.dir/flags.make
CMakeFiles/ch.dir/chameleonhash.cpp.o: ../chameleonhash.cpp
CMakeFiles/ch.dir/chameleonhash.cpp.o: CMakeFiles/ch.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qy/Documents/ChameleonHash/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ch.dir/chameleonhash.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/ch.dir/chameleonhash.cpp.o -MF CMakeFiles/ch.dir/chameleonhash.cpp.o.d -o CMakeFiles/ch.dir/chameleonhash.cpp.o -c /home/qy/Documents/ChameleonHash/chameleonhash.cpp

CMakeFiles/ch.dir/chameleonhash.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ch.dir/chameleonhash.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/qy/Documents/ChameleonHash/chameleonhash.cpp > CMakeFiles/ch.dir/chameleonhash.cpp.i

CMakeFiles/ch.dir/chameleonhash.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ch.dir/chameleonhash.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/qy/Documents/ChameleonHash/chameleonhash.cpp -o CMakeFiles/ch.dir/chameleonhash.cpp.s

# Object files for target ch
ch_OBJECTS = \
"CMakeFiles/ch.dir/chameleonhash.cpp.o"

# External object files for target ch
ch_EXTERNAL_OBJECTS =

ch: CMakeFiles/ch.dir/chameleonhash.cpp.o
ch: CMakeFiles/ch.dir/build.make
ch: CMakeFiles/ch.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/qy/Documents/ChameleonHash/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ch"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ch.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ch.dir/build: ch
.PHONY : CMakeFiles/ch.dir/build

CMakeFiles/ch.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ch.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ch.dir/clean

CMakeFiles/ch.dir/depend:
	cd /home/qy/Documents/ChameleonHash/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/qy/Documents/ChameleonHash /home/qy/Documents/ChameleonHash /home/qy/Documents/ChameleonHash/cmake-build-debug /home/qy/Documents/ChameleonHash/cmake-build-debug /home/qy/Documents/ChameleonHash/cmake-build-debug/CMakeFiles/ch.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ch.dir/depend

