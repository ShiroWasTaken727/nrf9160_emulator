# Get started

With this project, we would like to learn about the potential attack surfaces of the NRF9160 firmware. To find these, we have to do some reverse engineering (like finding interesting tasks/functionality/functions etc).

To start reversing, load the firmware in your favourite reverse engineering tool. We would recommend ghidra [7] (just get the latest version).

To load the firmware into ghidra we would recommend to set:
- `ISA` = Armv7-M Thumb little endian or ARM cortex/ Thumb little endian".
- `Base address` = 0x50000
- Run the "auto analysis" but uncheck "Non-Returning Functions - Discovered".

Add the following memory regions to the memory map (Name,Start,Size,Permissions):

```
- modem_reg_dump, 0x0, 0x1000, RW
- (ram, 0x50000, 0x1d865f, RWX) -> should be already mapped by Ghidra
- modem_fota_area, 0x240000, 0x40000, RW
- modem_m4_data_tcm, 0x800000, 0x40000, RW
- modem_system_ram, 0x20000000, 0x8000, RW
- modem_DSP_ram, 0x22000000, 0x20000, RW
- peripheral, 0x40000000, 0x20000000, RW
- system_SYS, 0xe0000000, 0x20000000, RW
```

An explanation for this can be found below. This part is not too important, so feel free to skip it.

# Memory mapping Explanation


Memory mappings (where code/data etc is mapped) can be difficult to find for firmware. Typically we don't really know anything about the chip or it's memory layout.
For some firmwares, there's a propietary header embedded in the firmware that tells you how the bootloader maps the firmware, but unfortunately we don't immediately see this for our firmware.

To start we simply map everything at 0x0.

We guess that the ISA is either Armv7-(M/R) or Armv8-(M/R). There isn't too much of a difference between these two ISAs, so we'll just use ARMv7-M for now. In Armv7-M system registers are memory mapped (MMIO). To find the standard memory regions we can use the documentation [1] and look for the address map (page 592) and the memory ranges for the System registers (page 595 onwards).

The first entry of the VTOR should point to the RESET handler. This handler i run whenever the system boots. As it sets up everything and does not return, it must end with an infinite loop (a branching instruction to the same instruction ~ b $pc+0x0). If we look for such an instruction, we find two: The first one is a really small function; The other one @0xa918 seems to resemble our RESET function. Now we look for this address in memory (search for 19 a9 ~ thumb bit).  Of which only one seems to be a pointer: @0x404 -> `0x0005a919`. If we look at the other data here, it clearly looks like an array of exception handlers. In other words, the code should be mapped at base 0x50000. 


If we search for strings in the binary, we find a few interesting strings (possibly related to memory mappings):
```
    at `start` + 0x18454 -> "modem_fota_area"
    at `start` + 0x18464 -> "modem_system_ram"
    at `start` + 0x18478 -> "modem_m4_data_tcm"
    at `start` + 0x1848c -> "modem_reg_dump"
```

To verify our mapping, we search in memory for the bytes (LSB) (64 84), for which we find (amongst others) start + 0x183f0, that stores the address 0x00608464. This confirms our hypothesis that the firmware should be mapped at 0x50000 (as 0x50000 + 0x18464 = 0x618464 == "modem_system_ram"). We see an array that likely maps the above sections to something like

```
    some_id: 0x12
    name: ptr_to_modem_reg_dump_string
    addr: 0x0
    size: 0xbc

    some_id: 0x13
    name: ptr_to_modem_m4_data_string
    addr: 0x800000
    size: 0x40000

    some_id: 0x13
    name: ptr_to_modem_system_ram_string
    addr: 0x20000000
    size: 0x8000

    some_id: 0x13
    name: ptr_to_modem_fota_area_string
    addr: 0x240800
    size: 0x3f800

```

We can also find the string "modem_DSP_ram" in memory at 0x61324. If we look at the cross references, we see that it is referenced in a nearby function that seems to be calling a function that maps in some memory at 0x675e2. The "modem_DSP_ram" region seems to be mapped at 0x22000000 with a size of 0x20000. 

If we look at other functions that call this mapping function, we can see that "rpc_app_list_data", "rpc_app_list_ctrl" and "rpc_modem_mem" are also mapped in with this function. However it seems that these regions are mapped in dynamically. Finally "rf_history_buffer.bin" seems to be mapped in already at 0x809b38.


# Firmware structure

The firmware's kernel and user code are shipped in one binary blob. The firmware implements (and initializes) a custom Real-Time Operating System (RTOS). In such OSes, components are divided into tasks. Each of these tasks implement some functionality and are able to communicate with each other. This is typically done through "message queues" (see tasks & message queues in [2]). We suspect the firmware being similar to the cellular modems inside mobile phones, implementing "tasks" and "message queues".

# Firmware Targets

We know that the AT task (handling ATtention commands) in particular can be interesting. Depending on the type of the AT command, they can be send over the serial port and can be used to control and configure the cellular modem.

# How to *run* the Firmware

We would like to *run* the firmware off-device, meaning that we have to *replicate* the original hardware environment (== *rehosting*) [3]. Potentially for this project, we can try to replicate the hardware environment with an emulator, which is in our opinion the most straight forward way. Our emulator of choice will is QEMU [3], but since we're (for this project) not going to bother with *full-system emulation*, we recommend to use Unicorn [4]. In very simple words, Unicorn allows us to run arm thumb code on regular processors (x86_64, ..). 


# References

[1] https://developer.arm.com/documentation/ddi0403/latest/ 

[2] https://hardwear.io/netherlands-2020/presentation/samsung-baseband-hardwear-io-nl-2020.pdf 

[3] https://dl.acm.org/doi/10.1145/3433210.3453093 

[4] https://github.com/qemu/qemu

[5] https://github.com/unicorn-engine/unicorn

[6] https://github.com/nationalsecurityagency/ghidra
