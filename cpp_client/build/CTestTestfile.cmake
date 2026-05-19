# CMake generated Testfile for 
# Source directory: /home/nathan/Eternal_Blue/cpp_client
# Build directory: /home/nathan/Eternal_Blue/cpp_client/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(unit_tests "/home/nathan/Eternal_Blue/cpp_client/build/eternal-blue-tests")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/nathan/Eternal_Blue/cpp_client/CMakeLists.txt;78;add_test;/home/nathan/Eternal_Blue/cpp_client/CMakeLists.txt;0;")
subdirs("_deps/json-build")
subdirs("_deps/doctest-build")
