#!/bin/bash

# --- Find your offsets with objdump ---
# Use the following command to get the full disassembly:
# objdump -S --disassemble=canary_test_overflow vmlinux
# objdump -S --disassemble=local_var_corruption_test vmlinux
# objdump -S --disassemble=recursive_corruption_test vmlinux
# Then search for your function names to find the instruction addresses.
# Your instruction offset is the address relative to the function's start.
# Your stack offset is the distance from the stack base (`%rbp`) to the variable.
echo "Make sure you have updated the offset values in this script."
read -p "Press Enter to continue..."


# --- Test Case 1: Canary Overflow ---
echo "=== Running Test Case 1: Canary Overflow ==="
FUNCTION=canary_test_overflow
INSTRUCTION_OFFSET="0x1b"
echo "${FUNCTION}+${INSTRUCTION_OFFSET}" > /proc/kstackwatch
echo "test1" > /proc/kstackwatch_test
echo ""
echo "-------------------------------------"
read -p "Press Enter to continue..."

# --- Test Case 2: Multi-threaded Local Variable Corruption ---
echo "=== Running Test Case 2: Multi-threaded Corruption ==="
FUNCTION=local_var_corruption_test
INSTRUCTION_OFFSET="0x28"
STACK_OFFSET="-0x10"
WRITE_SIZE="8"
echo "${FUNCTION}+${INSTRUCTION_OFFSET} ${STACK_OFFSET}:${WRITE_SIZE}" > /proc/kstackwatch
echo "test2" > /proc/kstackwatch_test
echo ""
echo "-------------------------------------"
read -p "Press Enter to continue..."

# --- Test Case 3: Recursive Corruption ---
echo "=== Running Test Case 3: Recursive Corruption ==="
FUNCTION=recursive_corruption_test
INSTRUCTION_OFFSET="0x14"
echo "${FUNCTION}+${INSTRUCTION_OFFSET}" > /proc/kstackwatch
echo "test3" > /proc/kstackwatch_test
echo ""
echo "-------------------------------------"
read -p "Press Enter to continue..."