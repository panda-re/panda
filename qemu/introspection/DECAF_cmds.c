/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

#include "DECAF_cmds.h"
//#include "procmod.h"

void do_guest_ps(Monitor *mon)
{
  //list_procs(mon);
  linux_ps(mon);
}

void do_guest_pt(Monitor* mon)
{
  linux_pt(mon);
}

void do_guest_modules(Monitor* mon, int pid)
{
  linux_print_mod(mon, pid); 
}

void do_sym_to_addr(Monitor* mon, int pid, const char* modName, const char* symName)
{
  get_symbol_address(mon, pid, modName, symName);
}
