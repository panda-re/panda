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
 * @file rr_api.h
 * @brief Record-Replay API.
 */
#pragma once
#include "panda/rr/rr_types.h"

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

int panda_vm_quit(void);
int panda_record_begin(const char *name, const char *snapshot);
int panda_record_end(void);
int panda_replay_begin(const char *name);
int panda_replay_end(void);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

static inline bool rr_in_replay(void) { return rr_control.mode == RR_REPLAY; }
static inline bool rr_in_record(void) { return rr_control.mode == RR_RECORD; }
static inline bool rr_replay_requested(void) { return rr_control.next == RR_REPLAY; }
static inline bool rr_record_requested(void) { return rr_control.next == RR_RECORD; }
static inline bool rr_off(void) { return rr_control.mode == RR_OFF; }
static inline bool rr_on(void) { return !rr_off(); }

