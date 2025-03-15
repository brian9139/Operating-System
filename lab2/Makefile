# indicating that target "all" and "clean" are not files
.PHONY: all clean

# set some variables
CC= gcc
CFLAGS= -Wall -Wextra -O3 -lpthread -lrt
OUTPUT_OPTION= -MMD -MP -o $@

SOURCE= sched_demo_313553054.c
OBJS= $(SOURCE:.c=.o)
DEPS= $(SOURCE:.c=.d)
TARGET= sched_demo_313553054

# first command of make
all: $(TARGET)

# import the dependencies of .h .c files from the compiler
-include $(DEPS)

# implicit targets
# %.o: %.c
#        $(CC) $^ -o $@ -c $(CFLAGS)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@	

clean:
	@rm -f $(TARGET) $(OBJS) $(DEPS)