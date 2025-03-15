# Makefile for the kfetch kernel module

# Kernel build directory
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

# Module name
MODULE_NAME := kfetch_mod_313553054

# Compiler flags
obj-m := $(MODULE_NAME).o

# Default target to build the module
all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

# Load the kernel module
load:
	sudo insmod $(MODULE_NAME).ko
	@echo "Module $(MODULE_NAME) loaded."
	@lsmod | grep $(MODULE_NAME)

# Unload the kernel module
unload:
	sudo rmmod $(MODULE_NAME)
	@echo "Module $(MODULE_NAME) unloaded."
	@lsmod | grep $(MODULE_NAME) || echo "Module not loaded."

# Clean build files
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

# Ensure the module can be built under any directory
.PHONY: all load unload clean
