import math
import struct
import unicornafl

from unicorn import *
from unicorn.arm_const import *


# we need to align the firmware size to 4KB for memory mapping
def align_size(bytes_size, four_kb=4096):
    return math.ceil(bytes_size / four_kb) * four_kb


def align_4_bytes(requested_size):
    return math.ceil(requested_size / 4) * 4


# hooks for tracing basic blocks and instructions (debugging)
# def hook_block(uc, address, size, user_data):
#     print(">>> Basic block at 0x%x, size = 0x%x" % (address, size))


# hooking code for svc instructions to handle system calls
def hook_code(uc, address, size, user_data):
    # print(">>> Instruction at 0x%x, size = 0x%x" % (address, size))
    global HEAP_PTR

    sleep = 0x000D7EE6
    free = 0x000D770E

    message_malloc = 0x000D7C16
    alloc_000d753e = 0x000D753E
    alloc_0005c0f4 = 0x0005C0F4

    send_AT_response = 0x000DCF5C

    FUN_000dd190 = 0x000DD190
    FUN_000d84bc = 0x000D84BC
    FUN_000db380 = 0x000DB380
    FUN_000d7ebc = 0x000D7EBC
    FUN_000da004 = 0x000DA004
    FUN_000131ce8 = 0x00131CE8  # pal_msg_send_to
    FUN_000d8562 = 0x000D8562
    FUN_000d84c4 = 0x000D84C4
    FUN_000d84ac = 0x000D84AC

    diag_tracing_functions = [
        0x0012D534,
        0x0012D55E,
        0x00066998,
        0x0012D348,
        0x0012CF40,
        0x00066A24,
    ]

    if address == FUN_000da004:
        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_R0, 0)  # return 0 = modem not busy
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == 0xDA7E0:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> At function entry, LR={hex(lr)}")

    if address == sleep:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Skipping sleep()")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == free:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Skipping free()")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == FUN_000dd190:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found FUN_000dd190. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d84bc:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found FUN_000d84bc. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000db380:
        # print(">>> Entered the parser function (FUN_000db380)")
        r0 = uc.reg_read(UC_ARM_REG_R0)
        # print(f">>> Parser function argument R0: {hex(r0)}")
    if address == FUN_000d7ebc:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found FUN_000d7ebc. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000131ce8:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found pal_msg_send_to. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d8562:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found FUN_000d8562. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d84c4:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found FUN_000d84c4. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d84ac:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Found FUN_000d84ac. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address in diag_tracing_functions:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(
        #     f">>> Found diag tracing function at {hex(address)}. Skipping and returning to LR: {hex(lr)}"
        # )
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == message_malloc or address == alloc_0005c0f4:
        requested_size = uc.reg_read(UC_ARM_REG_R0)
        # print(
        #     f">>> Found message_malloc. Allocating {requested_size} bytes at {hex(HEAP_PTR)}"
        # )
        if HEAP_PTR + requested_size > HEAP_MAX:
            # print(">>> Heap overflow detected. Cannot allocate more memory.")
            uc.reg_write(UC_ARM_REG_R0, 0)  # return null pointer
        else:
            uc.reg_write(UC_ARM_REG_R0, HEAP_PTR)  # return heap pointer
            HEAP_PTR += align_4_bytes(requested_size)

        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> Returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == alloc_000d753e:
        num = uc.reg_read(UC_ARM_REG_R0)
        type_size = uc.reg_read(UC_ARM_REG_R1)
        requested_size = num * type_size

        if requested_size == 0:
            # print(
            #     f">>> Warning: alloc_000d753e called with num={num}, type={type_size}. Returning null pointer."
            # )
            uc.reg_write(UC_ARM_REG_R0, 0)  # return null pointer
        elif HEAP_PTR + requested_size > HEAP_MAX:
            # print(f">>> alloc_000d753e: Heap overflow. Returning null pointer.")
            uc.reg_write(UC_ARM_REG_R0, 0)
        else:
            uc.reg_write(UC_ARM_REG_R0, HEAP_PTR)  # return heap pointer
            HEAP_PTR += align_4_bytes(requested_size)
        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == send_AT_response:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        response_bytes = bytes(uc.mem_read(r0, 32))
        response_text = response_bytes.split(b"\x00")[0]
        # print(f">>> send_AT_response: {response_text}")

    if address == 0x0:
        lr = uc.reg_read(UC_ARM_REG_LR)
        # print(f">>> ERROR: CPU jumped to 0x0. LR: {hex(lr)}")

        # force the emulator to stop instantly for a clean terminal output
        uc.emu_stop()
        return

    if address == 0xC0FFEE:
        # print(">>> Reached exit address ☕. Stopping emulation.")
        uc.emu_stop()
        return


def hook_memory_invalid(uc, memory_type, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    # print(f">>> Memory error at {hex(address)}, PC={hex(pc)}, LR={hex(lr)}")
    return False


# load the firmware into memory
FIRMWARE = open("modem_firmware.bin", "rb").read()
BASE_ADDRESS = 0x50000

# start at modem_system_ram end - 4 to avoid going over the edge
STACK_ADDRESS = 0x20000000 + 0x8000 - 4

# start the heap in the middle of the ram
HEAP_ADDRESS = 0x20005000
HEAP_MAX = 0x20007000  # heap size 8KB (arbitrary)
HEAP_PTR = HEAP_ADDRESS

# write AT string outside of heap to avoid overwriting in case of malloc
AT_STRING_ADDRESS = 0x20004000
MESSAGE_DATA_ADDR = 0x20003000

# emulation starting point: start of the process_message function in the firmware
process_message = 0x000DA7E0
EXIT_ADDRESS = 0xC0FFEE

# print("Emulating modem firmware...")
# print(f"Emulating: process_message - 0x{process_message:x}")

# set up Unicorn emulator
try:
    # initialize emulator in ARM mode and thumb mode for Cortex-M ISA
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    # map memory for the firmware needs to be aligned 4KB
    mu.mem_map(0x50000, align_size(len(FIRMWARE)))  # firmware ram

    # write the firmware to the mapped memory
    mu.mem_write(BASE_ADDRESS, FIRMWARE)

    # map memory regions
    mu.mem_map(0x0, 0x1000)  # modem_reg_dump
    mu.mem_map(0x240000, 0x40000)  # modem_fota_area
    mu.mem_map(0x800000, 0x8000)  # covers tcm_copy + tcm1
    mu.mem_map(0x80A000, 0x26000)  # covers tcm_copy2 + tcm2
    mu.mem_map(0x20000000, 0x8000)  # modem_system_ram
    mu.mem_map(0x22000000, 0x20000)  # modem_DSP_ram
    mu.mem_map(0x40000000, 0x20000000)  # peripheral
    mu.mem_map(0xE0000000, 0x20000000)  # system_SYS

    mu.mem_write(0x800000, FIRMWARE[0x19658 : 0x19658 + 0x7C8])
    mu.mem_write(0x80A000, FIRMWARE[0x16F238 : 0x16F238 + 0x1E88])

    # add hooks for memory errors and for svc instructions
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_memory_invalid)
    mu.hook_add(UC_HOOK_CODE, hook_code)

except UcError as e:
    # print(f"Failed: {e}")
    exit(1)


# per-round fuzzing function that will be called by UnicornAFL
def place_afl_bytes(uc, input_bytes, persistent_round, data):
    global HEAP_PTR

    # reject 14 byte inputs since message struct needs to be at least 14 bytes
    if len(input_bytes) < 14:
        return False

    HEAP_PTR = HEAP_ADDRESS

    # we need to set modem to 1 or else it returns 7 in AT_validate_dispatch meaning that the modem is not ready
    mu.mem_write(0x0080BE07, b"\x01")

    # construct message struct
    command_id = 1
    flags = 0xFFFF
    unknown_bytes = int.from_bytes(input_bytes[4:8], "little")
    data_ptr = AT_STRING_ADDRESS  # point to the AT string in memory
    data_len = int.from_bytes(input_bytes[12:16], "little")

    msg = struct.pack("<HHIII", command_id, flags, unknown_bytes, data_ptr, data_len)
    uc.mem_write(MESSAGE_DATA_ADDR, msg)

    # clear old data first
    uc.mem_write(AT_STRING_ADDRESS, b"\x00" * 256)

    # take remaining bytes as AT command string and add null terminator
    at_string = input_bytes[14 : 14 + data_len] + b"\x00"
    uc.mem_write(AT_STRING_ADDRESS, at_string)

    # Reset CPU state for this round
    uc.reg_write(UC_ARM_REG_R0, MESSAGE_DATA_ADDR)
    uc.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
    uc.reg_write(UC_ARM_REG_LR, EXIT_ADDRESS)
    uc.reg_write(UC_ARM_REG_PC, process_message | 1)  # set LSB for thumb mode

    return True


# start fuzzing with UnicornAFL
input_file = None

result = unicornafl.uc_afl_fuzz(
    uc=mu,
    input_file=input_file,  # set to none to let AFL generate its own inputs
    place_input_callback=place_afl_bytes,
    exits=[EXIT_ADDRESS],
)

# print(f"Fuzzing result: {result}")
