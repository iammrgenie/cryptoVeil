# Compiler
CXX := g++

# Compiler flags
CXXFLAGS := -std=c++11 -Wall -Wextra

# Target executable name
TARGET := test

# Source files
SRCS := main.cpp

# Object files derived from source files
OBJS := $(SRCS:.cpp=.o)

# Directories for header files and libraries
INCLUDE_DIR := /usr/local/include
LIB_DIR := /usr/local/lib/

# Libraries needed by your program
LIBS := -lcrypto -lrelic -lrelic_ec -lopenabe -Wl,--disable-new-dtags,-rpath,$(LIB_DIR)

# Build rule for the target executable
$(TARGET):	$(OBJS)
	$(CXX) $(CXXFLAGS) -L$(LIB_DIR) $(OBJS) $(LIBS) -o $(TARGET)

# Build rule for object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Clean rule to remove generated files
clean:
	rm -f $(OBJS) $(TARGET)
