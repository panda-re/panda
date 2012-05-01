// Support for several common scsi like command data block requests
//
// Copyright (C) 2010  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "util.h" // htonl
#include "disk.h" // struct disk_op_s
#include "blockcmd.h" // struct cdb_request_sense
#include "ata.h" // atapi_cmd_data
#include "ahci.h" // atapi_cmd_data
#include "usb-msc.h" // usb_cmd_data

// Route command to low-level handler.
static int
cdb_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    u8 type = GET_GLOBAL(op->drive_g->type);
    switch (type) {
    case DTYPE_ATAPI:
        return atapi_cmd_data(op, cdbcmd, blocksize);
    case DTYPE_USB:
        return usb_cmd_data(op, cdbcmd, blocksize);
    case DTYPE_AHCI:
        return ahci_cmd_data(op, cdbcmd, blocksize);
    default:
        op->count = 0;
        return DISK_RET_EPARAM;
    }
}

int
cdb_get_inquiry(struct disk_op_s *op, struct cdbres_inquiry *data)
{
    struct cdb_request_sense cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.command = CDB_CMD_INQUIRY;
    cmd.length = sizeof(*data);
    op->count = 1;
    op->buf_fl = data;
    return cdb_cmd_data(op, &cmd, sizeof(*data));
}

// Request SENSE
int
cdb_get_sense(struct disk_op_s *op, struct cdbres_request_sense *data)
{
    struct cdb_request_sense cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.command = CDB_CMD_REQUEST_SENSE;
    cmd.length = sizeof(*data);
    op->count = 1;
    op->buf_fl = data;
    return cdb_cmd_data(op, &cmd, sizeof(*data));
}

// Request capacity
int
cdb_read_capacity(struct disk_op_s *op, struct cdbres_read_capacity *data)
{
    struct cdb_read_capacity cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.command = CDB_CMD_READ_CAPACITY;
    op->count = 1;
    op->buf_fl = data;
    return cdb_cmd_data(op, &cmd, sizeof(*data));
}

// Read sectors.
int
cdb_read(struct disk_op_s *op)
{
    struct cdb_rwdata_10 cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.command = CDB_CMD_READ_10;
    cmd.lba = htonl(op->lba);
    cmd.count = htons(op->count);
    return cdb_cmd_data(op, &cmd, GET_GLOBAL(op->drive_g->blksize));
}
