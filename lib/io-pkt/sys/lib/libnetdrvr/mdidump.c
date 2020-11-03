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





/*
 * Description:
 *	Contains Routines for MDI/PHY Register Dump Operations.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <netdrvr/mdi.h>
#include <netdrvr/nicsupport.h>

/*
 * Function	: MDI_DumpRegisters()
 * Description	:
 *	Debugging Function, will dump out the PHY Registers and PhyData to
 *	screen / serial port etc. via 
 */
int
MDI_DumpRegisters(mdi_t *mdi, int PhyAddr)
{
	PhyData_t	*PhyData;
	char *Regs[] = {
		"Control          :", "Status           :", "PhyId1           :",
		"PhyId2           :", "AN Advertisement :", "AN LP Ability    :",
		"AN Expansion     :", "AN Next Page Tx  :", 0
	};

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 ||
	    mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	PhyData = mdi->PhyData[PhyAddr];

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "MDI Information :");
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s", PhyData->Desc);

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[MDI_BMCR],
	    mdi->Read(mdi->handle, PhyAddr, MDI_BMCR));
	
	mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);	/* Clear Any Latching */
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[MDI_BMSR], 
	    mdi->Read(mdi->handle, PhyAddr, MDI_BMSR));

	if (!PhyData->StatusReg)
		PhyData->StatusReg = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);

	if (PhyData->StatusReg & BMSR_EXTENDED_CAP) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[MDI_PHYID_1],
		    mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_1));
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[MDI_PHYID_2],
		    mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_2));
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[MDI_ANAR],
		    mdi->Read(mdi->handle, PhyAddr, MDI_ANAR));
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[MDI_ANLPAR],
		    mdi->Read(mdi->handle, PhyAddr, MDI_ANLPAR));
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[MDI_ANAE],
		    mdi->Read(mdi->handle, PhyAddr, MDI_ANAE));
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[MDI_ANPT],
		    mdi->Read(mdi->handle, PhyAddr, MDI_ANPT));
	}

	if (PhyData->StatusReg & BMSR_EXTENDED_CAP) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\tOUI: 0x%08x\tModel: 0x%02x\tRev: 0x%02x",
		    PhyData->VendorOUI, PhyData->Model, PhyData->Rev);
	}
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\tControl  : 0x%04X\tStatusReg : 0x%04X\tCurrState : %d",
	    PhyData->Control, PhyData->StatusReg, PhyData->CurrState);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\tSetSpeed : %d\tSetDuplex %d, SetAdvert %02X\tLdown : %d",
	    PhyData->SetSpeed, PhyData->SetDuplex,
	    PhyData->SetAdvert, mdi->LDownTest);

	switch (PhyData->VendorOUI) {
		case BROADCOM:
			if (PhyData->Model == BM5202)
				DumpVendor_BM5202(mdi, PhyAddr);
			break;
		case NATIONAL_SEMICONDUCTOR:
			switch (PhyData->Model) {
				case DP_83840:
					if (PhyData->Rev == DP_83840A)
						DumpVendor_DP83840A(mdi, PhyAddr);
					break;
				case DP_83843:
					DumpVendor_DP83843(mdi, PhyAddr);
					break;
				case DP_83620:
					DumpVendor_DP83620(mdi, PhyAddr);
					break;
			}
			break;
		case LEVEL_ONE:
			if (PhyData->Model == LXT_9746)
				DumpVendor_LXT9746(mdi, PhyAddr);
			break;
		case QUALITY_SEMICONDUCTOR:
			switch (PhyData->Model) {
				case QS6612_HUGH:
				case QS6612:
					DumpVendor_QS6612(mdi, PhyAddr);
					break;
			}
			break;
		case ICS:
			if (PhyData->Model == ICS1890)
				DumpVendor_ICS1890(mdi, PhyAddr);
			break;
		case INTEL:
			if (PhyData->Model == I82555)
				DumpVendor_I82555(mdi, PhyAddr);
			break;
		case DAVICOM:
			if (PhyData->Model == DM9101)
				DumpVendor_DM9101(mdi, PhyAddr);
			break;
		case MYSON:
			if (PhyData->Model == MTD972)
				DumpVendor_DP83840A(mdi, PhyAddr);
			break;
		case TDK:
			if (PhyData->Model == TDK78Q2120)
				DumpVendor_TDK78Q2120(mdi, PhyAddr);
			break;
		default:
			break;
	}

	return (MDI_SUCCESS);
}

void
DumpVendor_DP83840A(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = { 0, 0,
		"Disconnect Cnt   :", "False Carrier Cnt:", 0,
		"Rx Error Cnt     :", "Silicon Rev      :", "PCS Cfg          :",
		"LoopBack/Bypass  :", "PHY Address      :", 0,
		"10bT Status      :", "10bT Cfg         :", 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 2));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[3],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 3));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[5],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 5));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[6],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 6));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[7],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 7));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[8],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 8));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[9],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 9));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[0xB],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xB));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[0xC],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xC));
}

void
DumpVendor_DP83843(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"PHY Status       :", "MII Int. Ctrl    :", "MII Int Status   :",
		"Disconnect Cnt   :", "False Carrier Cnt:", "Rx Error Cnt     :",
		"PCS Cfg/Status   :", "LoopBack/Bypass  :", "10bT Status/Ctrl :",
		"PHY Control      :", 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 2));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[3],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 3));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[4],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 4));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[5],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 5));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[6],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 6));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[7],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 7));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[8],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 8));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[9],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 9));
}

void
DumpVendor_DP83620(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"PHYSTS       :", "MICR         :", "MISR         :",
		"PAGESEL      :", "FCSCR        :", "RECR         :",
		"PCSR         :", "RBR          :", "LEDCR        :",
		"PHYCR        :", "10BTSCR      :", "CDCTRL1      :",
		"PHYCR2       :", "EDCR         :", 0,
		"PCFCR        :", 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 2));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[3],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 3));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[4],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 4));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[5],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 5));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[6],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 6));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[7],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 7));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[8],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 8));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[9],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 9));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[10],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 10));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[11],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 11));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[12],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 12));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[13],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 13));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[15],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 15));
}


void
DumpVendor_LXT9746(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"Mirror           :", "Int Enable       :", "Int Status       :",
		"Configuration    :", "Chip Status      :", 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 2));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[3],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 3));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[4],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 4));
}

void
DumpVendor_QS6612(mdi_t *mdi, int PhyAddr)
{
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\tMode Control     : 0x%04X\t",
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Interrupt Src     : 0x%04X",
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xD));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\tInterrupt Msk    : 0x%04X\t",
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xE));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Base TX PHY Ctrl  : 0x%04X",
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xF));
}

void
DumpVendor_ICS1890(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"Extended Contrl  :", "QuickPoll Status :",
		"10bT Operation   :", "Extended Control :",
		 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 2));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[3],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 3));
}

void
DumpVendor_I82555(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"Control/Status   :", "Special Control  :", 0, 0,
		"100bT RxDis. Cnt :", "100bT RxErr Cnt  :",
		"RxErr Sym Cnt    :", "100bT PreEOF Cnt :",
		"10bT RxEOF Cnt   :", "10bT TxJab Cnt   :",
		"Special Control2 :", 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[4],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 4));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[5],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 5));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[6],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 6));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[7],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 7));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[8],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 8));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[9],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 9));

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[0xA],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xA));
}

void
DumpVendor_DM9101(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"Specified Config :", "Spec. Cfg/Status :",
		"10bT Cfg/Status  :", 0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X\t", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 1));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 2));
}

void
DumpVendor_BM5202(mdi_t *mdi, int PhyAddr)
{
	return;
}

/****************** TDK **********************/

/* TDK 78Q2120 */ 
void
DumpVendor_TDK78Q2120(mdi_t *mdi, int PhyAddr)
{
	char *Regs[] = {
		"MR16 Vendor Specific  :",
		"MR17 Interrupt Control:",
		"MR18 Diagnostic       :",
		0
	};

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[0],
	    mdi->Read(mdi->handle, PhyAddr, TDK_MR16));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[1],
	    mdi->Read(mdi->handle, PhyAddr, TDK_MR17));
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "\t%s 0x%04X", Regs[2],
	    mdi->Read(mdi->handle, PhyAddr, TDK_MR18));
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/mdidump.c $ $Rev: 836518 $")
#endif
