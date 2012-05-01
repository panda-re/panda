#!/usr/bin/perl -w

use warnings;
use strict;

use bytes;

use constant MAX_ROM_LEN => 1024*1024;
use constant PCI_OFF => 0x18;
use constant INDICATOR_OFF => 0x15;

my $total_len = 0;
my @romfiles = @ARGV
    or die "Usage: $0 rom-file-1 rom-file-2 ... > multi-rom-file\n";

while ( my $romfile = shift @romfiles ) {
  my $last = @romfiles ? 0 : 1;

  open ROM, "<$romfile" or die "Could not open $romfile: $!\n";
  my $len = read ( ROM, my $romdata, MAX_ROM_LEN )
      or die "Could not read $romfile: $!\n";
  close ROM;

  die "$romfile is not a ROM file\n"
      unless substr ( $romdata, 0, 2 ) eq "\x55\xAA";

  ( my $checklen ) = unpack ( 'C', substr ( $romdata, 2, 1 ) );
  $checklen *= 512;
  die "$romfile has incorrect length field $checklen (should be $len)\n"
      unless $len == $checklen;

  ( my $pci ) = unpack ( 'v', substr ( $romdata, PCI_OFF, 2 ) );
  die "Invalid PCI offset field in $romfile\n"
      if $pci >= $len;
  die "No PCIR signature in $romfile\n"
      unless substr ( $romdata, $pci, 4 ) eq "PCIR";
  
  ( my $indicator ) =
      unpack ( 'C', substr ( $romdata, $pci + INDICATOR_OFF, 1 ) );
  my $msg = sprintf ( "$romfile: indicator was %02x, ", $indicator );
  $indicator &= ! ( 1 << 7 );
  $indicator |= ( $last << 7 );
  $msg .= sprintf ( "now %02x\n", $indicator );
  substr ( $romdata, $pci + INDICATOR_OFF, 1 ) = pack ( 'C', $indicator );
  warn $msg;

  print $romdata;
}
