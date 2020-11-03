/*
 * $QNXLicenseC:
 * Copyright 2007, QNX Software Systems. All Rights Reserved.
 * 
 * You must obtain a written license from and pay applicable license fees to QNX 
 * Software Systems before you may reproduce, modify or distribute this software, 
 * or any work that includes all or part of this software.   Free development 
 * licenses are available for evaluation and non-commercial purposes.  For more 
 * information visit http://licensing.qnx.com or email licensing@qnx.com.
 *  
 * This file may contain contributions from others.  Please review this entire 
 * file for other proprietary rights or license notices, as well as the QNX 
 * Development Suite License Guide at http://licensing.qnx.com/license-guide/ 
 * for other information.
 * $
 */





#include <hw/inout.h>
#include <inttypes.h>
#include <unistd.h>

#define NS_BASE			0x00
#define NE2000_DATA		0x10		// REP IO data port
#define NE2000_RESET		0x1f		// read to reset
#define	NS_CR			(NS_BASE + 0x0)
#define	NS_0W_IMR  	  	(NS_BASE + 0xF)	// interrupt mask reg

// command register
#define	NS_CR_STP		0x01		// software reset cmd
#define	NS_CR_STA		0x02		// start NIC
#define	NS_CR_TXP		0x04		// tx pkt
#define	NS_CR_RD_NA		0x00		// rem dma cmd: not allowed
#define	NS_CR_RD_RR		0x08		// rem dma cmd: remote read
#define	NS_CR_RD_RW		0x10		// rem dma cmd: remote write
#define	NS_CR_RD_SP		0x18		// rem dma cmd: send pkt
#define	NS_CR_RD_AB		0x20		// rem dma cmd: abort
#define	NS_CR_PS0  		0x00		// select page zero regs
#define	NS_CR_PS1  		0x40		// select page one regs
#define	NS_CR_PS2  		0x80		// select page two regs

/*
 * This function can be called by ISA drivers to avoid lockup problems.
 * The ne2000 is very "sensitive".  This function is used to determine
 * if an ne2000 device resides at a particular base address before the
 * driver's own device detection code starts poking at registers.
 */
int
nic_ne2000(int iobase)
{
	uint8_t tmp;

	tmp = in8(iobase + NE2000_RESET);		// reset
	delay(10);
	out8(iobase + NE2000_RESET, tmp);
	delay(10);
	tmp = in8(iobase + NS_CR);			// read the command register
	if((tmp & NS_CR_STP) != NS_CR_STP) {		// STP powers up high
		return(1);
	}

	if((tmp & NS_CR_STA) != 0x00) {			// STA powers up lo
		return(1);
	}
	
	out8(iobase + NS_CR, 0xA1);			// switch to page 2
	tmp = in8(iobase + NS_0W_IMR);			// read IMR
	if((tmp & 0x7f) != 0) {				// IMR powers up zeroes
		return(1);
	}

	return(0);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/ne2000.c $ $Rev: 680336 $")
#endif
