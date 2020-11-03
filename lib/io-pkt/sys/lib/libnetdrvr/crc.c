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





#include <netdrvr/nicsupport.h>
#include <inttypes.h>

uint32_t
nic_calc_crc_le(const uint8_t *buf, int len)
{
	uint32_t	crc;
	uint32_t	carry;
	uint8_t		data;
	int		i, j;

	crc = 0xffffffff;
	for (i = 0; i < len; i++) {
		data = buf[i];
		for (j = 0; j < 8; j++) {
			carry = ((data ^ crc) & 0x01);
			crc >>= 1;
			data >>= 1;
			if (carry) {
				crc = crc ^ 0xedb88320UL;
			}
		}
	}
	return(crc);
}

uint32_t
nic_calc_crc_be(const uint8_t *buf, int len)
{
	uint32_t	crc;
	uint32_t	carry;
	uint8_t		data;
	int		i, j;

	crc = 0xffffffff;
	for (i = 0; i < len; i++) {
		data = buf[i];
		for (j = 0; j < 8; j++) {
			carry = ((crc & 0x80000000) ? 1 : 0) ^ (data & 0x01);
			crc <<= 1;
			data >>= 1;
			if (carry) {
				crc = (crc ^ 0x04c11db6) | carry;
			}
		}
	}

	return(crc);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/crc.c $ $Rev: 703003 $")
#endif
