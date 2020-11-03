/*
 * $QNXtpLicenseC:
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

#include <net/netbyte.h>


uint16_t
(htobe16)(uint16_t val)
{
	return ENDIAN_BE16(val);
}

uint32_t
(htobe32)(uint32_t val)
{
	return ENDIAN_BE32(val);
}

uint64_t
(htobe64)(uint64_t val)
{
	return ENDIAN_BE64(val);
}

uint16_t
(htole16)(uint16_t val)
{
	return ENDIAN_LE16(val);
}

uint32_t
(htole32)(uint32_t val)
{
	return ENDIAN_LE32(val);
}

uint64_t
(htole64)(uint64_t val)
{
	return ENDIAN_LE64(val);
}

uint16_t
(be16toh)(uint16_t val)
{
	return ENDIAN_BE16(val);
}

uint32_t
(be32toh)(uint32_t val)
{
	return ENDIAN_BE32(val);
}

uint64_t
(be64toh)(uint64_t val)
{
	return ENDIAN_BE64(val);
}

uint16_t
(le16toh)(uint16_t val)
{
	return ENDIAN_LE16(val);
}

uint32_t
(le32toh)(uint32_t val)
{
	return ENDIAN_LE32(val);
}

uint64_t
(le64toh)(uint64_t val)
{
	return ENDIAN_LE64(val);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/netbyte.c $ $Rev: 729877 $")
#endif
