// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#define S905D2_GPIO_BASE                0xff634400
#define S905D2_GPIO_LENGTH              0x400
#define S905D2_GPIO_A0_BASE             0xff800000
#define S905D2_GPIO_AO_LENGTH           0x1000
#define S905D2_GPIO_INTERRUPT_BASE      0xffd00000
#define S905D2_GPIO_INTERRUPT_LENGTH    0x10000

#define S905D2_USB0_BASE                0xff500000
#define S905D2_USB0_LENGTH              0x100000

#define S905D2_DOS_BASE                 0xff620000
#define S905D2_DOS_LENGTH               0x10000

#define S905D2_DMC_BASE                 0xff638000
#define S905D2_DMC_LENGTH               0x1000

#define S905D2_USBCTRL_BASE             0xffe09000
#define S905D2_USBCTRL_LENGTH           0x2000

#define S905D2_RESET_BASE               0xffd01000
#define S905D2_RESET_LENGTH             0x1000

#define S905D2_USBPHY20_BASE            0xff636000
#define S905D2_USBPHY20_LENGTH          0x2000

#define S905D2_USBPHY21_BASE            0xff63a000
#define S905D2_USBPHY21_LENGTH          0x2000

#define S905D2_HIU_BASE                 0xff63c000
#define S905D2_HIU_LENGTH               0x2000

#define S905D2_MALI_BASE                0xffe40000
#define S905D2_MALI_LENGTH              0x40000

#define S905D2_CBUS_BASE                0xffd00000
#define S905D2_CBUS_LENGTH              0x100000
#define S905D2_I2C0_BASE                (S905D2_CBUS_BASE + 0x1f000)
#define S905D2_I2C1_BASE                (S905D2_CBUS_BASE + 0x1e000)
#define S905D2_I2C2_BASE                (S905D2_CBUS_BASE + 0x1d000)
#define S905D2_I2C3_BASE                (S905D2_CBUS_BASE + 0x1c000)

#define S905D2_AOBUS_BASE               0xff800000
#define S905D2_AOBUS_LENGTH             0x100000

#define S905D2_I2C_AO_0_BASE            (S905D2_AOBUS_BASE + 0x5000)
//SDIO
#define S905D2_EMMC_A_SDIO_BASE         0xffe03000
#define S905D2_EMMC_A_SDIO_LENGTH       0x2000

#define S905D2_RAW_NAND_REG_BASE        (S905D2_AOBUS_BASE + 0x607800)
#define S905D2_RAW_NAND_CLOCK_BASE      (S905D2_AOBUS_BASE + 0x607000)

// Reset register offsets
#define S905D2_RESET0_REGISTER          0x04
#define S905D2_RESET1_REGISTER          0x08
#define S905D2_RESET1_USB               (1 << 2)    // bit to reset USB
#define S905D2_RESET2_REGISTER          0x0c
#define S905D2_RESET3_REGISTER          0x10
#define S905D2_RESET4_REGISTER          0x14
#define S905D2_RESET6_REGISTER          0x1c
#define S905D2_RESET7_REGISTER          0x20
#define S905D2_RESET0_MASK              0x40
#define S905D2_RESET1_MASK              0x44
#define S905D2_RESET2_MASK              0x48
#define S905D2_RESET3_MASK              0x4c
#define S905D2_RESET4_MASK              0x50
#define S905D2_RESET6_MASK              0x58
#define S905D2_RESET7_MASK              0x5c
#define S905D2_RESET0_LEVEL             0x80
#define S905D2_RESET1_LEVEL             0x84
#define S905D2_RESET2_LEVEL             0x88
#define S905D2_RESET3_LEVEL             0x8c
#define S905D2_RESET4_LEVEL             0x90
#define S905D2_RESET6_LEVEL             0x98
#define S905D2_RESET7_LEVEL             0x9c


#define S905D2_I2C0_IRQ                 53
#define S905D2_I2C1_IRQ                 246
#define S905D2_I2C2_IRQ                 247
#define S905D2_I2C3_IRQ                 71
#define S905D2_I2C_AO_0_IRQ             227

// Datasheet has incorrect number, but linux device tree seems correct.
#define S905D2_DEMUX_IRQ                55
#define S905D2_USB0_IRQ                 62
#define S905D2_PARSER_IRQ               64
#define S905D2_RAW_NAND_IRQ             66
#define S905D2_DOS_MBOX_0_IRQ           75
#define S905D2_DOS_MBOX_1_IRQ           76
#define S905D2_DOS_MBOX_2_IRQ           77
#define S905D2_GPIO_IRQ_0               96
#define S905D2_GPIO_IRQ_1               97
#define S905D2_GPIO_IRQ_2               98
#define S905D2_GPIO_IRQ_3               99
#define S905D2_GPIO_IRQ_4               100
#define S905D2_GPIO_IRQ_5               101
#define S905D2_GPIO_IRQ_6               102
#define S905D2_GPIO_IRQ_7               103
#define S905D2_MALI_IRQ_GP              192
#define S905D2_MALI_IRQ_GPMMU           193
#define S905D2_MALI_IRQ_PP              194
#define S905D2_A0_GPIO_IRQ_0            238
#define S905D2_A0_GPIO_IRQ_1            239

#define S905D2_EMMC_A_SDIO_IRQ          221


// Alternate Functions for SDIO
#define S905D2_WIFI_SDIO_D0           S905D2_GPIOX(0)
#define S905D2_WIFI_SDIO_D0_FN        1
#define S905D2_WIFI_SDIO_D1           S905D2_GPIOX(1)
#define S905D2_WIFI_SDIO_D1_FN        1
#define S905D2_WIFI_SDIO_D2           S905D2_GPIOX(2)
#define S905D2_WIFI_SDIO_D2_FN        1
#define S905D2_WIFI_SDIO_D3           S905D2_GPIOX(3)
#define S905D2_WIFI_SDIO_D3_FN        1
#define S905D2_WIFI_SDIO_CLK          S905D2_GPIOX(4)
#define S905D2_WIFI_SDIO_CLK_FN       1
#define S905D2_WIFI_SDIO_CMD          S905D2_GPIOX(5)
#define S905D2_WIFI_SDIO_CMD_FN       1
#define S905D2_WIFI_SDIO_WAKE_HOST    S905D2_GPIOX(7)
#define S905D2_WIFI_SDIO_WAKE_HOST_FN 1
