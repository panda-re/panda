#!/usr/bin/perl -w
#
# Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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

my $romfile = shift || "-";
my $rom = new Option::ROM;
$rom->load ( $romfile );

die "Not an option ROM image\n"
    unless $rom->{signature} == ROM_SIGNATURE;

my $romlength = ( $rom->{length} * 512 );
my $filelength = $rom->length;
die "ROM image truncated (is $filelength, should be $romlength)\n"
    if $filelength < $romlength;

printf "ROM header:\n\n";
printf "  %-16s 0x%02x (%d)\n", "Length:", $rom->{length}, ( $rom->{length} * 512 );
printf "  %-16s 0x%02x (%s0x%02x)\n", "Checksum:", $rom->{checksum},
       ( ( $rom->checksum == 0 ) ? "" : "INCORRECT: " ), $rom->checksum;
printf "  %-16s 0x%04x\n", "Init:", $rom->{init};
printf "  %-16s 0x%04x\n", "UNDI header:", $rom->{undi_header};
printf "  %-16s 0x%04x\n", "PCI header:", $rom->{pci_header};
printf "  %-16s 0x%04x\n", "PnP header:", $rom->{pnp_header};
printf "\n";

my $pci = $rom->pci_header();
if ( $pci ) {
  printf "PCI header:\n\n";
  printf "  %-16s %s\n", "Signature:", $pci->{signature};
  printf "  %-16s 0x%04x\n", "Vendor ID:", $pci->{vendor_id};
  printf "  %-16s 0x%04x\n", "Device ID:", $pci->{device_id};
  printf "  %-16s 0x%02x%02x%02x\n", "Device class:",
	 $pci->{base_class}, $pci->{sub_class}, $pci->{prog_intf};
  printf "  %-16s 0x%04x (%d)\n", "Image length:",
	 $pci->{image_length}, ( $pci->{image_length} * 512 );
  printf "  %-16s 0x%04x (%d)\n", "Runtime length:",
	 $pci->{runtime_length}, ( $pci->{runtime_length} * 512 );
  if ( exists $pci->{conf_header} ) {
    printf "  %-16s 0x%04x\n", "Config header:", $pci->{conf_header};
    printf "  %-16s 0x%04x\n", "CLP entry:", $pci->{clp_entry};
  }
  printf "\n";
}

my $pnp = $rom->pnp_header();
if ( $pnp ) {
  printf "PnP header:\n\n";
  printf "  %-16s %s\n", "Signature:", $pnp->{signature};
  printf "  %-16s 0x%02x (%s0x%02x)\n", "Checksum:", $pnp->{checksum},
	 ( ( $pnp->checksum == 0 ) ? "" : "INCORRECT: " ), $pnp->checksum;
  printf "  %-16s 0x%04x \"%s\"\n", "Manufacturer:",
	 $pnp->{manufacturer}, $pnp->manufacturer;
  printf "  %-16s 0x%04x \"%s\"\n", "Product:",
	 $pnp->{product}, $pnp->product;
  printf "  %-16s 0x%04x\n", "BCV:", $pnp->{bcv};
  printf "  %-16s 0x%04x\n", "BDV:", $pnp->{bdv};
  printf "  %-16s 0x%04x\n", "BEV:", $pnp->{bev};
  printf "\n";
}
