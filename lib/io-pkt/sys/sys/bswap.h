/*      $NetBSD: bswap.h,v 1.12 2006/05/22 16:28:27 drochner Exp $      */

/* Written by Manuel Bouyer. Public domain */

#ifndef _SYS_BSWAP_H_
#define _SYS_BSWAP_H_

#ifndef _LOCORE
#include <sys/cdefs.h>
#include <sys/types.h>

#include <machine/bswap.h>

__BEGIN_DECLS
/* Always declare the functions in case their address is taken (etc) */
#if defined(_KERNEL) || defined(_STANDALONE) || !defined(__BSWAP_RENAME)
uint16_t bswap16(uint16_t) __attribute__((__const__));
uint32_t bswap32(uint32_t) __attribute__((__const__));
#else
uint16_t bswap16(uint16_t) __RENAME(__bswap16) __attribute__((__const__));
uint32_t bswap32(uint32_t) __RENAME(__bswap32) __attribute__((__const__));
#endif
uint64_t bswap64(uint64_t) __attribute__((__const__));
__END_DECLS

#if defined(__GNUC__) && defined(__OPTIMIZE__)

/* machine/byte_swap.h might have defined inline versions */
#ifndef __BYTE_SWAP_U64_VARIABLE
#define	__BYTE_SWAP_U64_VARIABLE bswap64
#endif

#ifndef __BYTE_SWAP_U32_VARIABLE
#define	__BYTE_SWAP_U32_VARIABLE bswap32
#endif

#ifndef __BYTE_SWAP_U16_VARIABLE
#define	__BYTE_SWAP_U16_VARIABLE bswap16
#endif

#define	__byte_swap_u64_constant(x) \
	((uint64_t) \
	 ((((x) & 0xff00000000000000ull) >> 56) | \
	  (((x) & 0x00ff000000000000ull) >> 40) | \
	  (((x) & 0x0000ff0000000000ull) >> 24) | \
	  (((x) & 0x000000ff00000000ull) >>  8) | \
	  (((x) & 0x00000000ff000000ull) <<  8) | \
	  (((x) & 0x0000000000ff0000ull) << 24) | \
	  (((x) & 0x000000000000ff00ull) << 40) | \
	  (((x) & 0x00000000000000ffull) << 56)))

#define	__byte_swap_u32_constant(x) \
	((((x) & 0xff000000) >> 24) | \
	 (((x) & 0x00ff0000) >>  8) | \
	 (((x) & 0x0000ff00) <<  8) | \
	 (((x) & 0x000000ff) << 24))

#define	__byte_swap_u16_constant(x) \
	((((x) & 0xff00) >> 8) | \
	 (((x) & 0x00ff) << 8))

#define	bswap64(x) \
	(__builtin_constant_p((x)) ? \
	 __byte_swap_u64_constant(x) : __BYTE_SWAP_U64_VARIABLE(x))

#define	bswap32(x) \
	(__builtin_constant_p((x)) ? \
	 __byte_swap_u32_constant(x) : __BYTE_SWAP_U32_VARIABLE(x))

#define	bswap16(x) \
	(__builtin_constant_p((x)) ? \
	 __byte_swap_u16_constant(x) : __BYTE_SWAP_U16_VARIABLE(x))

#endif /* __GNUC__ && __OPTIMIZE__ */
#endif /* !_LOCORE */

#endif /* !_SYS_BSWAP_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/bswap.h $ $Rev: 680336 $")
#endif
