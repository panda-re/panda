/*

	mii.c: MII interface library

	Ported to iPXE by Daniel Verkamp <daniel@drv.nu>
	from Linux drivers/net/mii.c

	Maintained by Jeff Garzik <jgarzik@pobox.com>
	Copyright 2001,2002 Jeff Garzik

	Various code came from myson803.c and other files by
	Donald Becker.  Copyright:

		Written 1998-2002 by Donald Becker.

		This software may be used and distributed according
		to the terms of the GNU General Public License (GPL),
		incorporated herein by reference.  Drivers based on
		or derived from this code fall under the GPL and must
		retain the authorship, copyright and license notice.
		This file is not a complete program and may only be
		used when the entire operating system is licensed
		under the GPL.

		The author may be reached as becker@scyld.com, or C/O
		Scyld Computing Corporation
		410 Severn Ave., Suite 210
		Annapolis MD 21403

*/

#include <mii.h>

/**
 * mii_link_ok - is link status up/ok
 * @mii: the MII interface
 *
 * Returns 1 if the MII reports link status up/ok, 0 otherwise.
 */
int
mii_link_ok ( struct mii_if_info *mii )
{
	/* first, a dummy read, needed to latch some MII phys */
	mii->mdio_read ( mii->dev, mii->phy_id, MII_BMSR );
	if ( mii->mdio_read ( mii->dev, mii->phy_id, MII_BMSR ) & BMSR_LSTATUS )
		return 1;
	return 0;
}

/**
 * mii_check_link - check MII link status
 * @mii: MII interface
 *
 * If the link status changed (previous != current), call
 * netif_carrier_on() if current link status is Up or call
 * netif_carrier_off() if current link status is Down.
 */
void
mii_check_link ( struct mii_if_info *mii )
{
	int cur_link = mii_link_ok ( mii );
	int prev_link = netdev_link_ok ( mii->dev );

	if ( cur_link && !prev_link )
		netdev_link_up ( mii->dev );
	else if (prev_link && !cur_link)
		netdev_link_down ( mii->dev );
}


/**
 * mii_check_media - check the MII interface for a duplex change
 * @mii: the MII interface
 * @ok_to_print: OK to print link up/down messages
 * @init_media: OK to save duplex mode in @mii
 *
 * Returns 1 if the duplex mode changed, 0 if not.
 * If the media type is forced, always returns 0.
 */
unsigned int
mii_check_media ( struct mii_if_info *mii,
                  unsigned int ok_to_print,
                  unsigned int init_media )
{
	unsigned int old_carrier, new_carrier;
	int advertise, lpa, media, duplex;
	int lpa2 = 0;

	/* if forced media, go no further */
	if (mii->force_media)
		return 0; /* duplex did not change */

	/* check current and old link status */
	old_carrier = netdev_link_ok ( mii->dev ) ? 1 : 0;
	new_carrier = (unsigned int) mii_link_ok ( mii );

	/* if carrier state did not change, this is a "bounce",
	 * just exit as everything is already set correctly
	 */
	if ( ( ! init_media ) && ( old_carrier == new_carrier ) )
		return 0; /* duplex did not change */

	/* no carrier, nothing much to do */
	if ( ! new_carrier ) {
		netdev_link_down ( mii->dev );
		if ( ok_to_print )
			DBG ( "%s: link down\n", mii->dev->name);
		return 0; /* duplex did not change */
	}

	/*
	 * we have carrier, see who's on the other end
	 */
	netdev_link_up ( mii->dev );

	/* get MII advertise and LPA values */
	if ( ( ! init_media ) && ( mii->advertising ) ) {
		advertise = mii->advertising;
	} else {
		advertise = mii->mdio_read ( mii->dev, mii->phy_id, MII_ADVERTISE );
		mii->advertising = advertise;
	}
	lpa = mii->mdio_read ( mii->dev, mii->phy_id, MII_LPA );
	if ( mii->supports_gmii )
		lpa2 = mii->mdio_read ( mii->dev, mii->phy_id, MII_STAT1000 );

	/* figure out media and duplex from advertise and LPA values */
	media = mii_nway_result ( lpa & advertise );
	duplex = ( media & ADVERTISE_FULL ) ? 1 : 0;
	if ( lpa2 & LPA_1000FULL )
		duplex = 1;

	if ( ok_to_print )
		DBG ( "%s: link up, %sMbps, %s-duplex, lpa 0x%04X\n",
		       mii->dev->name,
		       lpa2 & ( LPA_1000FULL | LPA_1000HALF ) ? "1000" :
		       media & ( ADVERTISE_100FULL | ADVERTISE_100HALF ) ? "100" : "10",
		       duplex ? "full" : "half",
		       lpa);

	if ( ( init_media ) || ( mii->full_duplex != duplex ) ) {
		mii->full_duplex = duplex;
		return 1; /* duplex changed */
	}

	return 0; /* duplex did not change */
}
