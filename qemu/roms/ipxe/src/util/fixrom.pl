#!/usr/bin/perl -w
#
# Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin";
use Option::ROM qw ( :all );

my @romfiles = @ARGV;

foreach my $romfile ( @romfiles ) {
  my $rom = new Option::ROM;
  $rom->load ( $romfile );
  $rom->pnp_header->fix_checksum() if $rom->pnp_header;
  $rom->fix_checksum();
  $rom->save ( $romfile );
}
