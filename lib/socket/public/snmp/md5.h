/* 
** **************************************************************************
** md5.h -- Header file for implementation of MD5 Message Digest Algorithm **
** Updated: 2/13/90 by Ronald L. Rivest                                    **
** (C) 1990 RSA Data Security, Inc.                                        **
** **************************************************************************
*/

#ifndef _MD5_H_INCLUDED
#define _MD5_H_INCLUDED

#include <_pack64.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MDstruct is the data structure for a message digest computation.
*/
typedef struct {
  unsigned int buffer[4];    /* Holds 4-word result of MD computation */
  unsigned char count[8];    /* Number of bits processed so far */
  unsigned int done;         /* Nonzero means MD computation finished */
} MDstruct, *MDptr;

/* MDbegin(MD)
** Input: MD -- an MDptr
** Initialize the MDstruct prepatory to doing a message digest computation.
*/
extern void MDbegin();

/* MDupdate(MD,X,count)
** Input: MD -- an MDptr
**        X -- a pointer to an array of unsigned characters.
**        count -- the number of bits of X to use (an unsigned int).
** Updates MD using the first ``count'' bits of X.
** The array pointed to by X is not modified.
** If count is not a multiple of 8, MDupdate uses high bits of last byte.
** This is the basic input routine for a user.
** The routine terminates the MD computation when count < 512, so
** every MD computation should end with one call to MDupdate with a
** count less than 512.  Zero is OK for a count.
*/
extern void MDupdate();

/* MDprint(MD)
** Input: MD -- an MDptr
** Prints message digest buffer MD as 32 hexadecimal digits.
** Order is from low-order byte of buffer[0] to high-order byte of buffer[3].
** Each byte is printed with high-order hexadecimal digit first.
*/
extern void MDprint();      

/* 
** End of md5.h
****************************(cut)*****************************************/

#include <_packpop.h>

#ifdef __cplusplus
};
#endif
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/public/snmp/md5.h $ $Rev: 680336 $")
#endif
