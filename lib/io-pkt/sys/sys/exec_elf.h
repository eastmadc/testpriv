/*	$NetBSD: exec_elf.h,v 1.89.2.1 2007/07/09 10:30:55 liamjfoy Exp $	*/

/*-
 * Copyright (c) 1994 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_EXEC_ELF_H_
#define	_SYS_EXEC_ELF_H_

/*
 * The current ELF ABI specification is available at:
 *	http://www.sco.com/developers/gabi/
 *
 * Current header definitions are in:
 *	http://www.sco.com/developers/gabi/latest/ch4.eheader.html
 */

#if defined(_KERNEL) || defined(_STANDALONE)
#include <sys/types.h>
#else
#include <inttypes.h>
#endif /* _KERNEL || _STANDALONE */

#if defined(ELFSIZE)
#define	CONCAT(x,y)	__CONCAT(x,y)
#define	ELFNAME(x)	CONCAT(elf,CONCAT(ELFSIZE,CONCAT(_,x)))
#define	ELFNAME2(x,y)	CONCAT(x,CONCAT(_elf,CONCAT(ELFSIZE,CONCAT(_,y))))
#define	ELFNAMEEND(x)	CONCAT(x,CONCAT(_elf,ELFSIZE))
#define	ELFDEFNNAME(x)	CONCAT(ELF,CONCAT(ELFSIZE,CONCAT(_,x)))
#endif

#if HAVE_NBTOOL_CONFIG_H
#include <nbinclude/machine/elf_machdep.h>
#else
#include <machine/elf_machdep.h>
#endif

typedef	uint8_t  	Elf_Byte;

typedef	uint32_t	Elf32_Addr;
#define	ELF32_FSZ_ADDR	4
typedef	uint32_t	Elf32_Off;
#define	ELF32_FSZ_OFF	4
typedef	int32_t		Elf32_Sword;
#define	ELF32_FSZ_SWORD	4
typedef	uint32_t	Elf32_Word;
#define	ELF32_FSZ_WORD	4
typedef	uint16_t	Elf32_Half;
#define	ELF32_FSZ_HALF	2

typedef	uint64_t	Elf64_Addr;
#define	ELF64_FSZ_ADDR	8
typedef	uint64_t	Elf64_Off;
#define	ELF64_FSZ_OFF	8
typedef	int32_t		Elf64_Shalf;
#define	ELF64_FSZ_SHALF	4

#ifndef ELF64_FSZ_SWORD
typedef	int32_t		Elf64_Sword;
#define	ELF64_FSZ_SWORD	4
#endif /* ELF64_FSZ_SWORD */
#ifndef ELF64_FSZ_WORD
typedef	uint32_t	Elf64_Word;
#define	ELF64_FSZ_WORD	4
#endif /* ELF64_FSZ_WORD */

typedef	int64_t		Elf64_Sxword;
#define	ELF64_FSZ_XWORD	8
typedef	uint64_t	Elf64_Xword;
#define	ELF64_FSZ_XWORD	8
typedef	uint32_t	Elf64_Half;
#define	ELF64_FSZ_HALF	4
typedef	uint16_t	Elf64_Quarter;
#define	ELF64_FSZ_QUARTER 2

/*
 * ELF Header
 */
#define	ELF_NIDENT	16

typedef struct {
	unsigned char	e_ident[ELF_NIDENT];	/* Id bytes */
	Elf32_Half	e_type;			/* file type */
	Elf32_Half	e_machine;		/* machine type */
	Elf32_Word	e_version;		/* version number */
	Elf32_Addr	e_entry;		/* entry point */
	Elf32_Off	e_phoff;		/* Program hdr offset */
	Elf32_Off	e_shoff;		/* Section hdr offset */
	Elf32_Word	e_flags;		/* Processor flags */
	Elf32_Half      e_ehsize;		/* sizeof ehdr */
	Elf32_Half      e_phentsize;		/* Program header entry size */
	Elf32_Half      e_phnum;		/* Number of program headers */
	Elf32_Half      e_shentsize;		/* Section header entry size */
	Elf32_Half      e_shnum;		/* Number of section headers */
	Elf32_Half      e_shstrndx;		/* String table index */
} Elf32_Ehdr;

typedef struct {
	unsigned char	e_ident[ELF_NIDENT];	/* Id bytes */
	Elf64_Quarter	e_type;			/* file type */
	Elf64_Quarter	e_machine;		/* machine type */
	Elf64_Half	e_version;		/* version number */
	Elf64_Addr	e_entry;		/* entry point */
	Elf64_Off	e_phoff;		/* Program hdr offset */
	Elf64_Off	e_shoff;		/* Section hdr offset */
	Elf64_Half	e_flags;		/* Processor flags */
	Elf64_Quarter	e_ehsize;		/* sizeof ehdr */
	Elf64_Quarter	e_phentsize;		/* Program header entry size */
	Elf64_Quarter	e_phnum;		/* Number of program headers */
	Elf64_Quarter	e_shentsize;		/* Section header entry size */
	Elf64_Quarter	e_shnum;		/* Number of section headers */
	Elf64_Quarter	e_shstrndx;		/* String table index */
} Elf64_Ehdr;

/* e_ident offsets */
#define	EI_MAG0		0	/* '\177' */
#define	EI_MAG1		1	/* 'E'    */
#define	EI_MAG2		2	/* 'L'    */
#define	EI_MAG3		3	/* 'F'    */
#define	EI_CLASS	4	/* File class */
#define	EI_DATA		5	/* Data encoding */
#define	EI_VERSION	6	/* File version */
#define	EI_OSABI	7	/* Operating system/ABI identification */
#define	EI_ABIVERSION	8	/* ABI version */
#define	EI_PAD		9	/* Start of padding bytes up to EI_NIDENT*/
#define	EI_NIDENT	16	/* First non-ident header byte */

/* e_ident[EI_MAG0,EI_MAG3] */
#define	ELFMAG0		0x7f
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4

/* e_ident[EI_CLASS] */
#define	ELFCLASSNONE	0	/* Invalid class */
#define	ELFCLASS32	1	/* 32-bit objects */
#define	ELFCLASS64	2	/* 64-bit objects */
#define	ELFCLASSNUM	3

/* e_ident[EI_DATA] */
#define	ELFDATANONE	0	/* Invalid data encoding */
#define	ELFDATA2LSB	1	/* 2's complement values, LSB first */
#define	ELFDATA2MSB	2	/* 2's complement values, MSB first */

/* e_ident[EI_VERSION] */
#define	EV_NONE		0	/* Invalid version */
#define	EV_CURRENT	1	/* Current version */
#define	EV_NUM		2

/* e_ident[EI_OSABI] */
#define	ELFOSABI_SYSV		0	/* UNIX System V ABI */
#define	ELFOSABI_HPUX		1	/* HP-UX operating system */
#define ELFOSABI_NETBSD		2	/* NetBSD */
#define ELFOSABI_LINUX		3	/* GNU/Linux */
#define ELFOSABI_HURD		4	/* GNU/Hurd */
#define ELFOSABI_86OPEN		5	/* 86Open */
#define ELFOSABI_SOLARIS	6	/* Solaris */
#define ELFOSABI_MONTEREY	7	/* Monterey */
#define ELFOSABI_IRIX		8	/* IRIX */
#define ELFOSABI_FREEBSD	9	/* FreeBSD */
#define ELFOSABI_TRU64		10	/* TRU64 UNIX */
#define ELFOSABI_MODESTO	11	/* Novell Modesto */
#define ELFOSABI_OPENBSD	12	/* OpenBSD */
/* Unofficial OSABIs follow */
#define ELFOSABI_ARM		97	/* ARM */
#define	ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

/* e_type */
#define	ET_NONE		0	/* No file type */
#define	ET_REL		1	/* Relocatable file */
#define	ET_EXEC		2	/* Executable file */
#define	ET_DYN		3	/* Shared object file */
#define	ET_CORE		4	/* Core file */
#define	ET_NUM		5

#define	ET_LOOS		0xfe00	/* Operating system specific range */
#define	ET_HIOS		0xfeff
#define	ET_LOPROC	0xff00	/* Processor-specific range */
#define	ET_HIPROC	0xffff

/* e_machine */
#define	EM_NONE		0	/* No machine */
#define	EM_M32		1	/* AT&T WE 32100 */
#define	EM_SPARC	2	/* SPARC */
#define	EM_386		3	/* Intel 80386 */
#define	EM_68K		4	/* Motorola 68000 */
#define	EM_88K		5	/* Motorola 88000 */
#define	EM_486		6	/* Intel 80486 */
#define	EM_860		7	/* Intel 80860 */
#define	EM_MIPS		8	/* MIPS I Architecture */
#define	EM_S370		9	/* Amdahl UTS on System/370 */
#define	EM_MIPS_RS3_LE	10	/* MIPS RS3000 Little-endian */
			/* 11-14 - Reserved */
#define	EM_RS6000	11	/* IBM RS/6000 XXX reserved */
#define	EM_PARISC	15	/* Hewlett-Packard PA-RISC */
#define	EM_NCUBE	16	/* NCube XXX reserved */
#define	EM_VPP500	17	/* Fujitsu VPP500 */
#define	EM_SPARC32PLUS	18	/* Enhanced instruction set SPARC */
#define	EM_960		19	/* Intel 80960 */
#define	EM_PPC		20	/* PowerPC */
#define	EM_PPC64	21	/* 64-bit PowerPC */
			/* 22-35 - Reserved */
#define	EM_V800		36	/* NEC V800 */
#define	EM_FR20		37	/* Fujitsu FR20 */
#define	EM_RH32		38	/* TRW RH-32 */
#define	EM_RCE		39	/* Motorola RCE */
#define	EM_ARM		40	/* Advanced RISC Machines ARM */
#define	EM_ALPHA	41	/* DIGITAL Alpha */
#define	EM_SH		42	/* Hitachi Super-H */
#define	EM_SPARCV9	43	/* SPARC Version 9 */
#define	EM_TRICORE	44	/* Siemens Tricore */
#define	EM_ARC		45	/* Argonaut RISC Core */
#define	EM_H8_300	46	/* Hitachi H8/300 */
#define	EM_H8_300H	47	/* Hitachi H8/300H */
#define	EM_H8S		48	/* Hitachi H8S */
#define	EM_H8_500	49	/* Hitachi H8/500 */
#define	EM_IA_64	50	/* Intel Merced Processor */
#define	EM_MIPS_X	51	/* Stanford MIPS-X */
#define	EM_COLDFIRE	52	/* Motorola Coldfire */
#define	EM_68HC12	53	/* Motorola MC68HC12 */
#define	EM_MMA		54	/* Fujitsu MMA Multimedia Accelerator */
#define	EM_PCP		55	/* Siemens PCP */
#define	EM_NCPU		56	/* Sony nCPU embedded RISC processor */
#define	EM_NDR1		57	/* Denso NDR1 microprocessor */
#define	EM_STARCORE	58	/* Motorola Star*Core processor */
#define	EM_ME16		59	/* Toyota ME16 processor */
#define	EM_ST100	60	/* STMicroelectronics ST100 processor */
#define	EM_TINYJ	61	/* Advanced Logic Corp. TinyJ embedded family processor */
#define	EM_X86_64	62	/* AMD x86-64 architecture */
#define	EM_PDSP		63	/* Sony DSP Processor */
#define	EM_PDP10	64	/* Digital Equipment Corp. PDP-10 */
#define	EM_PDP11	65	/* Digital Equipment Corp. PDP-11 */
#define	EM_FX66		66	/* Siemens FX66 microcontroller */
#define	EM_ST9PLUS	67	/* STMicroelectronics ST9+ 8/16 bit microcontroller */
#define	EM_ST7		68	/* STMicroelectronics ST7 8-bit microcontroller */
#define	EM_68HC16	69	/* Motorola MC68HC16 Microcontroller */
#define	EM_68HC11	70	/* Motorola MC68HC11 Microcontroller */
#define	EM_68HC08	71	/* Motorola MC68HC08 Microcontroller */
#define	EM_68HC05	72	/* Motorola MC68HC05 Microcontroller */
#define	EM_SVX		73	/* Silicon Graphics SVx */
#define	EM_ST19		74	/* STMicroelectronics ST19 8-bit CPU */
#define	EM_VAX		75	/* Digital VAX */
#define	EM_CRIS		76	/* Axis Communications 32-bit embedded processor */
#define	EM_JAVELIN	77	/* Infineon Technologies 32-bit embedded CPU */
#define	EM_FIREPATH	78	/* Element 14 64-bit DSP processor */
#define	EM_ZSP		79	/* LSI Logic's 16-bit DSP processor */
#define	EM_MMIX		80	/* Donald Knuth's educational 64-bit processor */
#define	EM_HUANY	81	/* Harvard's machine-independent format */
#define	EM_PRISM	82	/* SiTera Prism */
#define	EM_AVR		83	/* Atmel AVR 8-bit microcontroller */
#define	EM_FR30		84	/* Fujitsu FR30 */
#define	EM_D10V		85	/* Mitsubishi D10V */
#define	EM_D30V		86	/* Mitsubishi D30V */
#define	EM_V850		87	/* NEC v850 */
#define	EM_M32R		88	/* Mitsubishi M32R */
#define	EM_MN10300	89	/* Matsushita MN10300 */
#define	EM_MN10200	90	/* Matsushita MN10200 */
#define	EM_PJ		91	/* picoJava */
#define	EM_OPENRISC	92	/* OpenRISC 32-bit embedded processor */
#define	EM_ARC_A5	93	/* ARC Cores Tangent-A5 */
#define	EM_XTENSA	94	/* Tensilica Xtensa Architecture */
#define	EM_NS32K	97	/* National Semiconductor 32000 series */

/* Unofficial machine types follow */
#define	EM_ALPHA_EXP	36902	/* used by NetBSD/alpha; obsolete */
#define	EM_NUM		36903

/*
 * Program Header
 */
typedef struct {
	Elf32_Word	p_type;		/* entry type */
	Elf32_Off	p_offset;	/* offset */
	Elf32_Addr	p_vaddr;	/* virtual address */
	Elf32_Addr	p_paddr;	/* physical address */
	Elf32_Word	p_filesz;	/* file size */
	Elf32_Word	p_memsz;	/* memory size */
	Elf32_Word	p_flags;	/* flags */
	Elf32_Word	p_align;	/* memory & file alignment */
} Elf32_Phdr;

typedef struct {
	Elf64_Half	p_type;		/* entry type */
	Elf64_Half	p_flags;	/* flags */
	Elf64_Off	p_offset;	/* offset */
	Elf64_Addr	p_vaddr;	/* virtual address */
	Elf64_Addr	p_paddr;	/* physical address */
	Elf64_Xword	p_filesz;	/* file size */
	Elf64_Xword	p_memsz;	/* memory size */
	Elf64_Xword	p_align;	/* memory & file alignment */
} Elf64_Phdr;

/* p_type */
#define	PT_NULL		0		/* Program header table entry unused */
#define	PT_LOAD		1		/* Loadable program segment */
#define	PT_DYNAMIC	2		/* Dynamic linking information */
#define	PT_INTERP	3		/* Program interpreter */
#define	PT_NOTE		4		/* Auxiliary information */
#define	PT_SHLIB	5		/* Reserved, unspecified semantics */
#define	PT_PHDR		6		/* Entry for header table itself */
#define	PT_NUM		7

#define	PT_LOOS         0x60000000	/* OS-specific range */
#define	PT_HIOS         0x6fffffff
#define	PT_LOPROC	0x70000000	/* Processor-specific range */
#define	PT_HIPROC	0x7fffffff

#define	PT_MIPS_REGINFO	0x70000000

/* p_flags */
#define	PF_R		0x4	/* Segment is readable */
#define	PF_W		0x2	/* Segment is writable */
#define	PF_X		0x1	/* Segment is executable */

#define	PF_MASKOS	0x0ff00000	/* Operating system specific values */
#define	PF_MASKPROC	0xf0000000	/* Processor-specific values */

/*
 * Section Headers
 */
typedef struct {
	Elf32_Word	sh_name;	/* section name (.shstrtab index) */
	Elf32_Word	sh_type;	/* section type */
	Elf32_Word	sh_flags;	/* section flags */
	Elf32_Addr	sh_addr;	/* virtual address */
	Elf32_Off	sh_offset;	/* file offset */
	Elf32_Word	sh_size;	/* section size */
	Elf32_Word	sh_link;	/* link to another */
	Elf32_Word	sh_info;	/* misc info */
	Elf32_Word	sh_addralign;	/* memory alignment */
	Elf32_Word	sh_entsize;	/* table entry size */
} Elf32_Shdr;

typedef struct {
	Elf64_Half	sh_name;	/* section name (.shstrtab index) */
	Elf64_Half	sh_type;	/* section type */
	Elf64_Xword	sh_flags;	/* section flags */
	Elf64_Addr	sh_addr;	/* virtual address */
	Elf64_Off	sh_offset;	/* file offset */
	Elf64_Xword	sh_size;	/* section size */
	Elf64_Half	sh_link;	/* link to another */
	Elf64_Half	sh_info;	/* misc info */
	Elf64_Xword	sh_addralign;	/* memory alignment */
	Elf64_Xword	sh_entsize;	/* table entry size */
} Elf64_Shdr;

/* sh_type */
#define	SHT_NULL	0		/* Section header table entry unused */
#define	SHT_PROGBITS	1		/* Program information */
#define	SHT_SYMTAB	2		/* Symbol table */
#define	SHT_STRTAB	3		/* String table */
#define	SHT_RELA	4		/* Relocation information w/ addend */
#define	SHT_HASH	5		/* Symbol hash table */
#define	SHT_DYNAMIC	6		/* Dynamic linking information */
#define	SHT_NOTE	7		/* Auxiliary information */
#define	SHT_NOBITS	8		/* No space allocated in file image */
#define	SHT_REL		9		/* Relocation information w/o addend */
#define	SHT_SHLIB	10		/* Reserved, unspecified semantics */
#define	SHT_DYNSYM	11		/* Symbol table for dynamic linker */
#define	SHT_NUM		12

#define	SHT_LOOS	0x60000000	/* Operating system specific range */
#define SHT_SUNW_VERDEF	0x6ffffffd	/* Versions defined by file */
#define SHT_SUNW_VERNEED 0x6ffffffe	/* Versions needed by file */
#define SHT_SUNW_VERSYM	0x6fffffff	/* Symbol versions */
#define	SHT_HIOS	0x6fffffff
#define	SHT_LOPROC	0x70000000	/* Processor-specific range */
#define	SHT_HIPROC	0x7fffffff
#define	SHT_LOUSER	0x80000000	/* Application-specific range */
#define	SHT_HIUSER	0xffffffff

/* sh_flags */
#define	SHF_WRITE	0x1		/* Section contains writable data */
#define	SHF_ALLOC	0x2		/* Section occupies memory */
#define	SHF_EXECINSTR	0x4		/* Section contains executable insns */

#define	SHF_MASKOS	0x0f000000	/* Operating system specific values */
#define	SHF_MASKPROC	0xf0000000	/* Processor-specific values */

/*
 * Symbol Table
 */
typedef struct {
	Elf32_Word	st_name;	/* Symbol name (.symtab index) */
	Elf32_Word	st_value;	/* value of symbol */
	Elf32_Word	st_size;	/* size of symbol */
	Elf_Byte	st_info;	/* type / binding attrs */
	Elf_Byte	st_other;	/* unused */
	Elf32_Half	st_shndx;	/* section index of symbol */
} Elf32_Sym;

typedef struct {
	Elf64_Half	st_name;	/* Symbol name (.symtab index) */
	Elf_Byte	st_info;	/* type / binding attrs */
	Elf_Byte	st_other;	/* unused */
	Elf64_Quarter	st_shndx;	/* section index of symbol */
	Elf64_Addr	st_value;	/* value of symbol */
	Elf64_Xword	st_size;	/* size of symbol */
} Elf64_Sym;

/* Symbol Table index of the undefined symbol */
#define	ELF_SYM_UNDEFINED	0

#define STN_UNDEF		0	/* undefined index */

/* st_info: Symbol Bindings */
#define	STB_LOCAL		0	/* local symbol */
#define	STB_GLOBAL		1	/* global symbol */
#define	STB_WEAK		2	/* weakly defined global symbol */
#define	STB_NUM			3

#define	STB_LOOS		10	/* Operating system specific range */
#define	STB_HIOS		12
#define	STB_LOPROC		13	/* Processor-specific range */
#define	STB_HIPROC		15

/* st_info: Symbol Types */
#define	STT_NOTYPE		0	/* Type not specified */
#define	STT_OBJECT		1	/* Associated with a data object */
#define	STT_FUNC		2	/* Associated with a function */
#define	STT_SECTION		3	/* Associated with a section */
#define	STT_FILE		4	/* Associated with a file name */
#define	STT_NUM			5

#define	STT_LOOS		10	/* Operating system specific range */
#define	STT_HIOS		12
#define	STT_LOPROC		13	/* Processor-specific range */
#define	STT_HIPROC		15

/* st_other: Visibility Types */
#define	STV_DEFAULT		0	/* use binding type */
#define	STV_INTERNAL		1	/* not referenced from outside */
#define	STV_HIDDEN		2	/* not visible, may be used via ptr */
#define	STV_PROTECTED		3	/* visible, not preemptible */

/* st_info/st_other utility macros */
#define	ELF_ST_BIND(info)		((uint32_t)(info) >> 4)
#define	ELF_ST_TYPE(info)		((uint32_t)(info) & 0xf)
#define	ELF_ST_INFO(bind,type)		((Elf_Byte)(((bind) << 4) | \
					 ((type) & 0xf)))
#define	ELF_ST_VISIBILITY(other)	((uint32_t)(other) & 3)

/*
 * Special section indexes
 */
#define	SHN_UNDEF	0		/* Undefined section */

#define	SHN_LORESERVE	0xff00		/* Reserved range */
#define	SHN_ABS		0xfff1		/*  Absolute symbols */
#define	SHN_COMMON	0xfff2		/*  Common symbols */
#define	SHN_HIRESERVE	0xffff

#define	SHN_LOPROC	0xff00		/* Processor-specific range */
#define	SHN_HIPROC	0xff1f
#define	SHN_LOOS	0xff20		/* Operating system specific range */
#define	SHN_HIOS	0xff3f

#define	SHN_MIPS_ACOMMON 0xff00
#define	SHN_MIPS_TEXT	0xff01
#define	SHN_MIPS_DATA	0xff02
#define	SHN_MIPS_SCOMMON 0xff03

/*
 * Relocation Entries
 */
typedef struct {
	Elf32_Word	r_offset;	/* where to do it */
	Elf32_Word	r_info;		/* index & type of relocation */
} Elf32_Rel;

typedef struct {
	Elf32_Word	r_offset;	/* where to do it */
	Elf32_Word	r_info;		/* index & type of relocation */
	Elf32_Sword	r_addend;	/* adjustment value */
} Elf32_Rela;

/* r_info utility macros */
#define	ELF32_R_SYM(info)	((info) >> 8)
#define	ELF32_R_TYPE(info)	((info) & 0xff)
#define	ELF32_R_INFO(sym, type)	(((sym) << 8) + (unsigned char)(type))

typedef struct {
	Elf64_Addr	r_offset;	/* where to do it */
	Elf64_Xword	r_info;		/* index & type of relocation */
} Elf64_Rel;

typedef struct {
	Elf64_Addr	r_offset;	/* where to do it */
	Elf64_Xword	r_info;		/* index & type of relocation */
	Elf64_Sxword	r_addend;	/* adjustment value */
} Elf64_Rela;

/* r_info utility macros */
#define	ELF64_R_SYM(info)	((info) >> 32)
#define	ELF64_R_TYPE(info)	((info) & 0xffffffff)
#define	ELF64_R_INFO(sym,type)	(((sym) << 32) + (type))

/*
 * Dynamic Section structure array
 */
typedef struct {
	Elf32_Word	d_tag;		/* entry tag value */
	union {
	    Elf32_Addr	d_ptr;
	    Elf32_Word	d_val;
	} d_un;
} Elf32_Dyn;

typedef struct {
	Elf64_Xword	d_tag;		/* entry tag value */
	union {
	    Elf64_Addr	d_ptr;
	    Elf64_Xword	d_val;
	} d_un;
} Elf64_Dyn;

/* d_tag */
#define	DT_NULL		0	/* Marks end of dynamic array */
#define	DT_NEEDED	1	/* Name of needed library (DT_STRTAB offset) */
#define	DT_PLTRELSZ	2	/* Size, in bytes, of relocations in PLT */
#define	DT_PLTGOT	3	/* Address of PLT and/or GOT */
#define	DT_HASH		4	/* Address of symbol hash table */
#define	DT_STRTAB	5	/* Address of string table */
#define	DT_SYMTAB	6	/* Address of symbol table */
#define	DT_RELA		7	/* Address of Rela relocation table */
#define	DT_RELASZ	8	/* Size, in bytes, of DT_RELA table */
#define	DT_RELAENT	9	/* Size, in bytes, of one DT_RELA entry */
#define	DT_STRSZ	10	/* Size, in bytes, of DT_STRTAB table */
#define	DT_SYMENT	11	/* Size, in bytes, of one DT_SYMTAB entry */
#define	DT_INIT		12	/* Address of initialization function */
#define	DT_FINI		13	/* Address of termination function */
#define	DT_SONAME	14	/* Shared object name (DT_STRTAB offset) */
#define	DT_RPATH	15	/* Library search path (DT_STRTAB offset) */
#define	DT_SYMBOLIC	16	/* Start symbol search within local object */
#define	DT_REL		17	/* Address of Rel relocation table */
#define	DT_RELSZ	18	/* Size, in bytes, of DT_REL table */
#define	DT_RELENT	19	/* Size, in bytes, of one DT_REL entry */
#define	DT_PLTREL	20 	/* Type of PLT relocation entries */
#define	DT_DEBUG	21	/* Used for debugging; unspecified */
#define	DT_TEXTREL	22	/* Relocations might modify non-writable seg */
#define	DT_JMPREL	23	/* Address of relocations associated with PLT */
#define	DT_BIND_NOW	24	/* Process all relocations at load-time */
#define	DT_INIT_ARRAY	25	/* Address of initialization function array */
#define	DT_FINI_ARRAY	26	/* Size, in bytes, of DT_INIT_ARRAY array */
#define	DT_INIT_ARRAYSZ	27	/* Address of termination function array */
#define	DT_FINI_ARRAYSZ	28	/* Size, in bytes, of DT_FINI_ARRAY array*/
#define	DT_NUM		29

#define	DT_LOOS		0x60000000	/* Operating system specific range */
#define DT_VERSYM	0x6ffffff0	/* Symbol versions */
#define DT_VERDEF	0x6ffffffc	/* Versions defined by file */
#define DT_VERDEFNUM	0x6ffffffd	/* Number of versions defined by file */
#define DT_VERNEED	0x6ffffffe	/* Versions needed by file */
#define DT_VERNEEDNUM	0x6fffffff	/* Number of versions needed by file */
#define	DT_HIOS		0x6fffffff
#define	DT_LOPROC	0x70000000	/* Processor-specific range */
#define	DT_HIPROC	0x7fffffff

/*
 * Auxiliary Vectors
 */
typedef struct {
	Elf32_Word	a_type;				/* 32-bit id */
	Elf32_Word	a_v;				/* 32-bit id */
} Aux32Info;

typedef struct {
	Elf64_Half	a_type;				/* 32-bit id */
	Elf64_Xword	a_v;				/* 64-bit id */
} Aux64Info;

/* a_type */
#define	AT_NULL		0	/* Marks end of array */
#define	AT_IGNORE	1	/* No meaning, a_un is undefined */
#define	AT_EXECFD	2	/* Open file descriptor of object file */
#define	AT_PHDR		3	/* &phdr[0] */
#define	AT_PHENT	4	/* sizeof(phdr[0]) */
#define	AT_PHNUM	5	/* # phdr entries */
#define	AT_PAGESZ	6	/* PAGESIZE */
#define	AT_BASE		7	/* Interpreter base addr */
#define	AT_FLAGS	8	/* Processor flags */
#define	AT_ENTRY	9	/* Entry address of executable */
#define	AT_DCACHEBSIZE	10	/* Data cache block size */
#define	AT_ICACHEBSIZE	11	/* Instruction cache block size */
#define	AT_UCACHEBSIZE	12	/* Unified cache block size */

	/* Vendor specific */
#define	AT_MIPS_NOTELF	10	/* XXX a_val != 0 -> MIPS XCOFF executable */

#define	AT_EUID		2000	/* euid (solaris compatible numbers) */
#define	AT_RUID		2001	/* ruid (solaris compatible numbers) */
#define	AT_EGID		2002	/* egid (solaris compatible numbers) */
#define	AT_RGID		2003	/* rgid (solaris compatible numbers) */

	/* Solaris kernel specific */
#define	AT_SUN_LDELF	2004	/* dynamic linker's ELF header */
#define	AT_SUN_LDSHDR	2005	/* dynamic linker's section header */
#define	AT_SUN_LDNAME	2006	/* dynamic linker's name */
#define	AT_SUN_LPGSIZE	2007	/* large pagesize */

	/* Other information */
#define	AT_SUN_PLATFORM	2008	/* sysinfo(SI_PLATFORM) */
#define	AT_SUN_HWCAP	2009	/* process hardware capabilities */
#define	AT_SUN_IFLUSH	2010	/* do we need to flush the instruction cache? */
#define	AT_SUN_CPU	2011	/* CPU name */
	/* ibcs2 emulation band aid */
#define	AT_SUN_EMUL_ENTRY 2012	/* coff entry point */
#define	AT_SUN_EMUL_EXECFD 2013	/* coff file descriptor */
	/* Executable's fully resolved name */
#define	AT_SUN_EXECNAME	2014

/*
 * Note Headers
 */
typedef struct {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
} Elf32_Nhdr;

typedef struct {
	Elf64_Half n_namesz;
	Elf64_Half n_descsz;
	Elf64_Half n_type;
} Elf64_Nhdr;

#define	ELF_NOTE_TYPE_ABI_TAG		1

/* GNU-specific note name and description sizes */
#define	ELF_NOTE_ABI_NAMESZ		4
#define	ELF_NOTE_ABI_DESCSZ		16
/* GNU-specific note name */
#define	ELF_NOTE_ABI_NAME		"GNU\0"

/* GNU-specific OS/version value stuff */
#define	ELF_NOTE_ABI_OS_LINUX		0
#define	ELF_NOTE_ABI_OS_HURD		1
#define	ELF_NOTE_ABI_OS_SOLARIS		2

/* NetBSD-specific note type: Emulation name.  desc is emul name string. */
#define	ELF_NOTE_TYPE_NETBSD_TAG	1
/* NetBSD-specific note name and description sizes */
#define	ELF_NOTE_NETBSD_NAMESZ		7
#define	ELF_NOTE_NETBSD_DESCSZ		4
/* NetBSD-specific note name */
#define	ELF_NOTE_NETBSD_NAME		"NetBSD\0\0"

/* NetBSD-specific note type: Checksum.  There should be 1 NOTE per PT_LOAD
   section.  desc is a tuple of <phnum>(16),<chk-type>(16),<chk-value>. */
#define	ELF_NOTE_TYPE_CHECKSUM_TAG	2
#define	ELF_NOTE_CHECKSUM_CRC32		1
#define	ELF_NOTE_CHECKSUM_MD5		2
#define	ELF_NOTE_CHECKSUM_SHA1		3
#define	ELF_NOTE_CHECKSUM_SHA256	4

/* NetBSD-specific note type: PaX.  There should be 1 NOTE per executable.
   section.  desc is a 32 bit bitmask */
#define ELF_NOTE_TYPE_PAX_TAG		3
#define	ELF_NOTE_PAX_MPROTECT		0x1	/* Force enable Mprotect */
#define	ELF_NOTE_PAX_NOMPROTECT		0x2	/* Force disable Mprotect */
#define	ELF_NOTE_PAX_GUARD		0x4	/* Force enable Segvguard */
#define	ELF_NOTE_PAX_NOGUARD		0x8	/* Force disable Servguard */
#define ELF_NOTE_PAX_NAMESZ		4
#define ELF_NOTE_PAX_NAME		"PaX\0"
#define ELF_NOTE_PAX_DESCSZ		4

/*
 * NetBSD-specific core file information.
 *
 * NetBSD ELF core files use notes to provide information about
 * the process's state.  The note name is "NetBSD-CORE" for
 * information that is global to the process, and "NetBSD-CORE@nn",
 * where "nn" is the lwpid of the LWP that the information belongs
 * to (such as register state).
 *
 * We use the following note identifiers:
 *
 *	ELF_NOTE_NETBSD_CORE_PROCINFO
 *		Note is a "netbsd_elfcore_procinfo" structure.
 *
 * We also use ptrace(2) request numbers (the ones that exist in
 * machine-dependent space) to identify register info notes.  The
 * info in such notes is in the same format that ptrace(2) would
 * export that information.
 *
 * Please try to keep the members of this structure nicely aligned,
 * and if you add elements, add them to the end and bump the version.
 */

#define	ELF_NOTE_NETBSD_CORE_NAME	"NetBSD-CORE"

#define	ELF_NOTE_NETBSD_CORE_PROCINFO	1

#define	NETBSD_ELFCORE_PROCINFO_VERSION	1

struct netbsd_elfcore_procinfo {
	/* Version 1 fields start here. */
	uint32_t	cpi_version;	/* netbsd_elfcore_procinfo version */
	uint32_t	cpi_cpisize;	/* sizeof(netbsd_elfcore_procinfo) */
	uint32_t	cpi_signo;	/* killing signal */
	uint32_t	cpi_sigcode;	/* signal code */
	uint32_t	cpi_sigpend[4];	/* pending signals */
	uint32_t	cpi_sigmask[4];	/* blocked signals */
	uint32_t	cpi_sigignore[4];/* blocked signals */
	uint32_t	cpi_sigcatch[4];/* blocked signals */
	int32_t		cpi_pid;	/* process ID */
	int32_t		cpi_ppid;	/* parent process ID */
	int32_t		cpi_pgrp;	/* process group ID */
	int32_t		cpi_sid;	/* session ID */
	uint32_t	cpi_ruid;	/* real user ID */
	uint32_t	cpi_euid;	/* effective user ID */
	uint32_t	cpi_svuid;	/* saved user ID */
	uint32_t	cpi_rgid;	/* real group ID */
	uint32_t	cpi_egid;	/* effective group ID */
	uint32_t	cpi_svgid;	/* saved group ID */
	uint32_t	cpi_nlwps;	/* number of LWPs */
	int8_t		cpi_name[32];	/* copy of p->p_comm */
	/* Add version 2 fields below here. */
	int32_t		cpi_siglwp;	/* LWP target of killing signal */
};

#if defined(ELFSIZE) && (ELFSIZE == 32)
#define	Elf_Ehdr	Elf32_Ehdr
#define	Elf_Phdr	Elf32_Phdr
#define	Elf_Shdr	Elf32_Shdr
#define	Elf_Sym		Elf32_Sym
#define	Elf_Rel		Elf32_Rel
#define	Elf_Rela	Elf32_Rela
#define	Elf_Dyn		Elf32_Dyn
#define	Elf_Word	Elf32_Word
#define	Elf_Sword	Elf32_Sword
#define	Elf_Addr	Elf32_Addr
#define	Elf_Off		Elf32_Off
#define	Elf_Nhdr	Elf32_Nhdr

#define	ELF_R_SYM	ELF32_R_SYM
#define	ELF_R_TYPE	ELF32_R_TYPE
#define	ELFCLASS	ELFCLASS32

#define	AuxInfo		Aux32Info
#elif defined(ELFSIZE) && (ELFSIZE == 64)
#define	Elf_Ehdr	Elf64_Ehdr
#define	Elf_Phdr	Elf64_Phdr
#define	Elf_Shdr	Elf64_Shdr
#define	Elf_Sym		Elf64_Sym
#define	Elf_Rel		Elf64_Rel
#define	Elf_Rela	Elf64_Rela
#define	Elf_Dyn		Elf64_Dyn
#define	Elf_Word	Elf64_Word
#define	Elf_Sword	Elf64_Sword
#define	Elf_Addr	Elf64_Addr
#define	Elf_Off		Elf64_Off
#define	Elf_Nhdr	Elf64_Nhdr

#define	ELF_R_SYM	ELF64_R_SYM
#define	ELF_R_TYPE	ELF64_R_TYPE
#define	ELFCLASS	ELFCLASS64

#define	AuxInfo		Aux64Info
#endif

#define	ELF32_ST_BIND(info)		ELF_ST_BIND(info)
#define	ELF32_ST_TYPE(info)		ELF_ST_TYPE(info)
#define	ELF32_ST_INFO(bind,type)	ELF_ST_INFO(bind,type)
#define	ELF32_ST_VISIBILITY(other)	ELF_ST_VISIBILITY(other)

#define	ELF64_ST_BIND(info)		ELF_ST_BIND(info)
#define	ELF64_ST_TYPE(info)		ELF_ST_TYPE(info)
#define	ELF64_ST_INFO(bind,type)	ELF_ST_INFO(bind,type)
#define	ELF64_ST_VISIBILITY(other)	ELF_ST_VISIBILITY(other)

#ifdef _KERNEL

#define ELF_AUX_ENTRIES	12		/* Size of aux array passed to loader */
#define ELF32_NO_ADDR	(~(Elf32_Addr)0) /* Indicates addr. not yet filled in */
#define ELF32_LINK_ADDR	((Elf32_Addr)-2) /* advises to use link address */
#define ELF64_NO_ADDR	(~(Elf64_Addr)0) /* Indicates addr. not yet filled in */
#define ELF64_LINK_ADDR	((Elf64_Addr)-2) /* advises to use link address */

#if defined(ELFSIZE) && (ELFSIZE == 64)
#define ELF_NO_ADDR	ELF64_NO_ADDR
#define ELF_LINK_ADDR	ELF64_LINK_ADDR
#elif defined(ELFSIZE) && (ELFSIZE == 32)
#define ELF_NO_ADDR	ELF32_NO_ADDR
#define ELF_LINK_ADDR	ELF32_LINK_ADDR
#endif

#ifndef ELF32_EHDR_FLAGS_OK
#define	ELF32_EHDR_FLAGS_OK(eh)	1
#endif

#ifndef ELF64_EHDR_FLAGS_OK
#define	ELF64_EHDR_FLAGS_OK(eh)	1
#endif

#if defined(ELFSIZE) && (ELFSIZE == 64)
#define	ELF_EHDR_FLAGS_OK(eh)	ELF64_EHDR_FLAGS_OK(eh)
#else
#define	ELF_EHDR_FLAGS_OK(eh)	ELF32_EHDR_FLAGS_OK(eh)
#endif

#if defined(ELFSIZE)
struct elf_args {
        Elf_Addr  arg_entry;      /* program entry point */
        Elf_Addr  arg_interp;     /* Interpreter load address */
        Elf_Addr  arg_phaddr;     /* program header address */
        Elf_Addr  arg_phentsize;  /* Size of program header */
        Elf_Addr  arg_phnum;      /* Number of program headers */
};
#endif

/*
 * These constants are used for Elf32_Verdef struct's version number.  
 */
#define VER_DEF_NONE		0
#define	VER_DEF_CURRENT		1

/*
 * These constants are used for Elf32_Verdef struct's vd_flags.  
 */
#define VER_FLG_BASE		0x1
#define	VER_FLG_WEAK		0x2

/*
 * These are used in an Elf32_Versym field.
 */
#define	VER_NDX_LOCAL		0
#define	VER_NDX_GLOBAL		1

/*
 * These constants are used for Elf32_Verneed struct's version number.  
 */
#define	VER_NEED_NONE		0
#define	VER_NEED_CURRENT	1

/*
 * GNU Extension hidding symb
 */
#define	VERSYM_HIDDEN		0x8000
#define	VERSYM_VERSION		0x7fff

#define	ELF_VER_CHR		'@'

/*
 * These are current size independent.
 */

typedef struct {
	Elf32_Half	vd_version;	/* version number of structure */
	Elf32_Half	vd_flags;	/* flags (VER_FLG_*) */
	Elf32_Half	vd_ndx;		/* version index */
	Elf32_Half	vd_cnt;		/* number of verdaux entries */
	Elf32_Word	vd_hash;	/* hash of name */
	Elf32_Word	vd_aux;		/* offset to verdaux entries */
	Elf32_Word	vd_next;	/* offset to next verdef */
} Elf32_Verdef;

typedef struct {
	Elf32_Word	vda_name;	/* string table offset of name */
	Elf32_Word	vda_next;	/* offset to verdaux */
} Elf32_Verdaux;

typedef struct {
	Elf32_Half	vn_version;	/* version number of structure */
	Elf32_Half	vn_cnt;		/* number of vernaux entries */
	Elf32_Word	vn_file;	/* string table offset of library name*/
	Elf32_Word	vn_aux;		/* offset to vernaux entries */
	Elf32_Word	vn_next;	/* offset to next verneed */
} Elf32_Verneed;

typedef struct {
	Elf32_Word	vna_hash;	/* Hash of dependency name */
	Elf32_Half	vna_flags;	/* flags (VER_FLG_*) */
	Elf32_Half	vna_other;	/* unused */
	Elf32_Word	vna_name;	/* string table offset to version name*/
	Elf32_Word	vna_next;	/* offset to next vernaux */
} Elf32_Vernaux;

typedef struct {
	Elf32_Half	vs_vers;
} Elf32_Versym;

#ifndef _LKM
#include "opt_execfmt.h"
#endif

#ifdef EXEC_ELF32
int	exec_elf32_makecmds(struct lwp *, struct exec_package *);
int	elf32_copyargs(struct lwp *, struct exec_package *,
    	    struct ps_strings *, char **, void *);

int	coredump_elf32(struct lwp *, void *);
int	coredump_writenote_elf32(struct proc *, void *, Elf32_Nhdr *,
	    const char *, void *);

int	elf32_check_header(Elf32_Ehdr *, int);
#endif

#ifdef EXEC_ELF64
int	exec_elf64_makecmds(struct lwp *, struct exec_package *);
int	elf64_copyargs(struct lwp *, struct exec_package *,
	    struct ps_strings *, char **, void *);

int	coredump_elf64(struct lwp *, void *);
int	coredump_writenote_elf64(struct proc *, void *, Elf64_Nhdr *,
	    const char *, void *);

int	elf64_check_header(Elf64_Ehdr *, int);
#endif

#endif /* _KERNEL */

#endif /* !_SYS_EXEC_ELF_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/exec_elf.h $ $Rev: 680336 $")
#endif
