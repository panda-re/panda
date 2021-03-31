/*
 * Record and Replay for QEMU
 *
 * Copyright (c) 2007-2011 Massachusetts Institute of Technology
 *
 * Authors:
 *   Tim Leek <tleek@ll.mit.edu>
 *   Michael Zhivich <mzhivich@ll.mit.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */
/*!
 * @file rr_types.h
 * @brief Record-Replay related types and variables that need to be exposed to
 * different components of PANDA. This header is meant to be kept lean, so it
 * can be included without dragging any other PANDA/QEMU headers with it.
 * Any types/declarations that need access to target-specific state should be
 * pushed to other header files.
 */
#pragma once
#include <stdbool.h>    /* bool type */
#include <signal.h>     /* sig_atomic_t */

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

/** @brief Memory types. */
typedef enum { RR_MEM_IO, RR_MEM_RAM, RR_MEM_UNKNOWN } RR_mem_type;

/**
 * @brief Record/Replay modes. Also used to request transitions from one
 * mode to another.
 */
typedef enum { RR_NOCHANGE=-1, RR_OFF=0, RR_RECORD, RR_REPLAY } RR_mode;

/** @brief Return codes for functions controlling record/replay. */
typedef enum { 
    RRCTRL_EINVALID=-2, /* invalid mode transition requested */
    RRCTRL_EPENDING=-1, /* another transition is already pending */
    RRCTRL_OK=0         /* transition request registered */
} RRCTRL_ret;

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

/** @brief Structure encapsulating requests to change the record/replay status. */
typedef struct {
    volatile sig_atomic_t mode;
    volatile sig_atomic_t next;
    char *name;
    char *snapshot;
} rr_control_t;

/** @brief Global encapsulating requests to switch between PANDA modes. */
extern rr_control_t rr_control;

