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





#include <malloc.h>
#include <stdio.h>
#include <nbutil.h>

static char *__fgl_line;
static size_t __fgl_bufsize;

char *
fgetln_r(FILE *stream, size_t *lenp, char **bufp, size_t *buflenp)
{
	size_t base_size, ndone;
	char *base, *p;
	char *temp;

	if (bufp == NULL) {
		bufp = &__fgl_line;
		buflenp = &__fgl_bufsize;
	}

	base = *bufp;
	base_size = *buflenp;

	ndone = 0;

	flockfile(stream);

	for (;;) {
		p = base + ndone;

		for (; p < base + base_size; p++) {
			int ic;

			if ((ic = fgetc(stream)) == EOF) {
				if (ferror(stream))
					ndone = 0;
				goto out;
			}

			ndone++;
			if ((*p = ic) == '\n')
				goto out;
		}

		/* need more room */
		if ((temp = realloc(base, base_size + BUFSIZ)) == NULL) {
			ndone = 0;
			break;
		}

		base = temp;
		base_size += BUFSIZ;
	} 
out:
	funlockfile(stream);

	*bufp = base;
	*buflenp = base_size;
		
	if (ndone) {
		*lenp = ndone;
		return (base);
	}

	return NULL;
}

char *
fgetln(FILE *stream, size_t *len)
{
	return (fgetln_r(stream, len, NULL, NULL));
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/common/lib/libc/stdio/fgetln.c $ $Rev: 680336 $")
#endif
