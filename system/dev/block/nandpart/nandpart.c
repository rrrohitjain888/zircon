// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ddk/debug.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <ddk/binding.h>
#include <ddk/metadata.h>
#include <ddk/protocol/nand.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zircon/boot/image.h>
#include <zircon/hw/gpt.h>
#include <zircon/types.h>

#define GUID_STRLEN 40

#define TXN_SIZE 0x4000 // 128 partition entries

typedef struct {
    zx_device_t* zxdev;
    zx_device_t* parent;

    nand_protocol_t proto;
    zbi_partition_t part;

    nand_info_t info;
} nandpart_device_t;

struct guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

static void uint8_to_guid_string(char* dst, uint8_t* src) {
    struct guid* guid = (struct guid*)src;
    sprintf(dst, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", guid->data1, guid->data2,
            guid->data3, guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3],
            guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);
}

// implement device protocol:

/*
static zx_status_t nandpart_ioctl(void* ctx, uint32_t op, const void* cmd, size_t cmdlen,
                                  void* reply, size_t max, size_t* out_actual) {
    nandpart_device_t* device = ctx;
    switch (op) {
    case IOCTL_BLOCK_GET_INFO: {
        block_info_t* info = reply;
        if (max < sizeof(*info))
            return ZX_ERR_BUFFER_TOO_SMALL;
        memcpy(info, &device->info, sizeof(*info));
        *out_actual = sizeof(*info);
        return ZX_OK;
    }
    case IOCTL_BLOCK_GET_TYPE_GUID: {
        char* guid = reply;
        if (max < ZBI_PARTITION_GUID_LEN) return ZX_ERR_BUFFER_TOO_SMALL;
        memcpy(guid, device->part.type_guid, ZBI_PARTITION_GUID_LEN);
        return ZBI_PARTITION_GUID_LEN;
        *out_actual = ZBI_PARTITION_GUID_LEN;
        return ZX_OK;
    }
    case IOCTL_BLOCK_GET_PARTITION_GUID: {
        char* guid = reply;
        if (max < ZBI_PARTITION_GUID_LEN) return ZX_ERR_BUFFER_TOO_SMALL;
        memcpy(guid, device->part.uniq_guid, ZBI_PARTITION_GUID_LEN);
        *out_actual = ZBI_PARTITION_GUID_LEN;
        return ZX_OK;
    }
    case IOCTL_BLOCK_GET_NAME: {
        char* name = reply;
        strlcpy(name, device->part.name, max);
        *out_actual = strlen(name) + 1;
        return ZX_OK;
    }
    case IOCTL_DEVICE_SYNC: {
        // Propagate sync to parent device
        return device_ioctl(device->parent, IOCTL_DEVICE_SYNC, NULL, 0, NULL, 0, NULL);
    }
    default:
        return ZX_ERR_NOT_SUPPORTED;
    }
}
*/


static void nandpart_query(void* ctx, nand_info_t* info_out, size_t* nand_op_size_out) {

}

static void nandpart_queue(void* ctx, nand_op_t* op) {

}

static void nandpart_get_bad_block_list(void* ctx, uint32_t* bad_blocks, uint32_t bad_block_len,
                                        uint32_t* num_bad_blocks) {
}

static void nandpart_unbind(void* ctx) {
    nandpart_device_t* device = ctx;
    device_remove(device->zxdev);
}

static void nandpart_release(void* ctx) {
    nandpart_device_t* device = ctx;
    free(device);
}

static zx_off_t nandpart_get_size(void* ctx) {
    nandpart_device_t* dev = ctx;
    //TODO: use query() results, *but* fvm returns different query and getsize
    // results, and the latter are dynamic...
    return device_get_size(dev->parent);
}

static zx_protocol_device_t device_proto = {
    .version = DEVICE_OPS_VERSION,
//    .ioctl = nandpart_ioctl,
    .get_size = nandpart_get_size,
    .unbind = nandpart_unbind,
    .release = nandpart_release,
};

static nand_protocol_ops_t nand_ops = {
    .query = nandpart_query,
    .queue = nandpart_queue,
    .get_bad_block_list = nandpart_get_bad_block_list,
};

static zx_status_t nandpart_bind(void* ctx, zx_device_t* parent) {
printf("nandpart_bind\n");
    nand_protocol_t proto;
    uint8_t buffer[METADATA_PARTITION_MAP_MAX];
    size_t actual;

    if (device_get_protocol(parent, ZX_PROTOCOL_NAND, &proto) != ZX_OK) {
        zxlogf(ERROR, "nandpart: parent device '%s': does not support raw_nand protocol\n",
               device_get_name(parent));
        return ZX_ERR_NOT_SUPPORTED;
    }

    zx_status_t status = device_get_metadata(parent, DEVICE_METADATA_PARTITION_MAP, buffer,
                                             sizeof(buffer), &actual);
    if (status != ZX_OK) {
        zxlogf(ERROR, "nandpart: parent device '%s' has no parititon map\n",
               device_get_name(parent));
        return status;
    }

    zbi_partition_map_t* pmap = (zbi_partition_map_t*)buffer;
    if (pmap->partition_count == 0) {
        zxlogf(ERROR, "nandpart: partition_count is zero\n");
        return ZX_ERR_INTERNAL;
    }

    nand_info_t nand_info;
    size_t size = sizeof(nand_info);
    proto.ops->query(proto.ctx, &nand_info, &size);

    const uint8_t fvm_guid[] = GUID_FVM_VALUE;

    for (unsigned i = 0; i < pmap->partition_count; i++) {
        zbi_partition_t* part = &pmap->partitions[i];
        char name[128];
        char type_guid[GUID_STRLEN];
        char uniq_guid[GUID_STRLEN];

        snprintf(name, sizeof(name), "part-%03u", i);
        uint8_to_guid_string(type_guid, part->type_guid);
        uint8_to_guid_string(uniq_guid, part->uniq_guid);

        zxlogf(SPEW, "nandpart: partition %u (%s) type=%s guid=%s name=%s first=0x%"
               PRIx64 " last=0x%" PRIx64 "\n", i, name, type_guid, uniq_guid, part->name,
               part->first_block, part->last_block);

        nandpart_device_t* device = calloc(1, sizeof(nandpart_device_t));
        if (!device) {
            return ZX_ERR_NO_MEMORY;
        }

        device->parent = parent;
        memcpy(&device->proto, &proto, sizeof(device->proto));
        memcpy(&device->part, part, sizeof(device->part));

        memcpy(&device->info, &nand_info, sizeof(nand_info));
        memcpy(&device->info.partition_guid, &part->type_guid, sizeof(device->info.partition_guid));
        // adjust num_blocks based on partition size
        uint64_t partition_size = (part->last_block - part->first_block + 1) * pmap->block_size;
        device->info.num_blocks = partition_size / (nand_info.page_size * nand_info.pages_per_block);

        if (memcmp(part->type_guid, fvm_guid, sizeof(fvm_guid)) == 0) {
             // we only use FTL for the FVM partition
             device->info.nand_class = NAND_CLASS_FTL;
         } else {
             device->info.nand_class = NAND_CLASS_RAW;
         }

        zx_device_prop_t props[] = {
            { BIND_PROTOCOL, 0, ZX_PROTOCOL_NAND },
            { BIND_NAND_CLASS, 0, device->info.nand_class },
        };

        device_add_args_t args = {
            .version = DEVICE_ADD_ARGS_VERSION,
            .name = name,
            .ctx = device,
            .ops = &device_proto,
            .proto_id = ZX_PROTOCOL_NAND,
            .proto_ops = &nand_ops,
            .props = props,
            .prop_count = countof(props),
            .flags = DEVICE_ADD_INVISIBLE,
        };

        zx_status_t status = device_add(parent, &args, &device->zxdev);
        if (status != ZX_OK) {
            free(device);
            return status;
        }

        // add empty partition map metadata to prevent this driver from binding to its child devices
        status = device_add_metadata(device->zxdev, DEVICE_METADATA_PARTITION_MAP, NULL, 0);
        if (status != ZX_OK) {
            device_remove(device->zxdev);
            free(device);
            continue;
        }

        // make device visible after adding metadata
        device_make_visible(device->zxdev);
    }

    return ZX_OK;
}

static zx_driver_ops_t nandpart_driver_ops = {
    .version = DRIVER_OPS_VERSION,
    .bind = nandpart_bind,
};

ZIRCON_DRIVER_BEGIN(nandpart, nandpart_driver_ops, "zircon", "0.1", 2)
    BI_ABORT_IF(NE, BIND_PROTOCOL, ZX_PROTOCOL_NAND),
    BI_MATCH_IF(EQ, BIND_NAND_CLASS, NAND_CLASS_PARTMAP),
ZIRCON_DRIVER_END(nandpart)
