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
 *	Contains Routines for MDI/PHY Operations.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <netdrvr/mdi.h>
#include <sys/slogcodes.h>
#include <netdrvr/nicsupport.h>

/* Debugging Stuff */

/* #define MDI_DEBUG */

#ifdef	MDI_DEBUG
#define	MDI_TRACE	(1<<0)
#define	MDI_DUMP	(1<<1)
int	MdiDebug = 0xffffffff;
#endif

/*
 * Generic MDI Interface.....
 */

/*
 * Function	: MDI_Register_Extended()
 *            Note: same as original MDI_Register routin except we supply
 *                  the priority & timer interval for the callback routines
 *
 *
 * Description	:
 *	Allow Registration/Creation of your MDI interface.
 *  The caller must supply a valid Read, Write & Callback function
 *  a valid mdi pointer & a valid event pointer to be used for all
 *  subsequent MDI calls.
 *  The timer that is created by this function will fire once every
 *  MDI_CALLBACKTIME (currently 3) seconds & has a priority of 21
 *
 *  NOTE: The caller must call MDI_DeRegister function to free memory
 *        that was allocated by this function.
 *
 * Returns : MDI_SUCCESS if registration is correct.
 *           anything else is considered an error & no further
 *           MDI routines should be used by the caller
 */
int
MDI_Register_Extended (void *handle, MDIWriteFunc write, MDIReadFunc read,
     MDICallBack callback, mdi_t **mdi, struct sigevent *event,
     int priority, int callback_interval)
{
	mdi_t	*mmdi;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_Register_extended(0x%p, 0x%p, 0x%p, 0x%p)",
		    write, read, callback, mdi);
#endif

	if ((mmdi = (mdi_t *)calloc(1, sizeof (mdi_t))) == NULL)
		return (MDI_NOMEM);

	mmdi->handle	= handle;
	mmdi->Read	= read;
	mmdi->Write	= write;
	mmdi->CallBack	= (callback) ? callback : NULL;
	mmdi->DisableMonitor = 1;
	mmdi->CallBackTimer = -1;

	if (mmdi->CallBack != NULL && event != NULL) {
		/*
		 * Setup the Callback Timer.
		 * Used on a PER MDI basis.
		 */
		event->sigev_notify	= SIGEV_PULSE;
		event->sigev_code	= MDI_TIMER;
		event->sigev_priority	= priority;

		if ((timer_create(CLOCK_REALTIME, event,
		    &mmdi->CallBackTimer)) == -1) {
			free(mmdi);
			return (MDI_TIMER_FAILURE);
		}	

		mmdi->CBTimer.it_value.tv_sec = callback_interval;
		mmdi->CBTimer.it_value.tv_nsec = 0L;
		mmdi->CBTimer.it_interval.tv_sec = callback_interval;
		mmdi->CBTimer.it_interval.tv_nsec = 0L;
		if (timer_settime(mmdi->CallBackTimer, 0, &mmdi->CBTimer,
		    NULL) == -1) {
			timer_delete(mmdi->CallBackTimer);
			free(mmdi);
			return (MDI_TIMER_FAILURE);
		}
	}

	*mdi = mmdi;
	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_Register()
 *
 * Description	:
 *	Allow Registration/Creation of your MDI interface.
 *  The caller must supply a valid Read, Write & Callback function
 *  a valid mdi pointer & a valid event pointer to be used for all
 *  subsequent MDI calls.
 *  The timer that is created by this function will fire once every
 *  MDI_CALLBACKTIME (currently 3) seconds & has a priority of 21
 *
 *  NOTE: The caller must call MDI_DeRegister function to free memory
 *        that was allocated by this function.
 *
 * Returns : MDI_SUCCESS if registration is correct.
 *           anything else is considered an error & no further
 *           MDI routines should be used by the caller
 */
int
MDI_Register(void *handle, MDIWriteFunc write, MDIReadFunc read,
     MDICallBack callback, mdi_t **mdi, struct sigevent *event)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_Register(0x%p, 0x%p, 0x%p, 0x%p)",
		    write, read, callback, mdi);
#endif

	return (MDI_Register_Extended (handle, write, read, callback, mdi, event, 21,
			MDI_CALLBACKTIME));
}

/*
 * Function	: MDI_DeRegister()
 *
 * Description	:
 *	Deregister from MDI, delete the callback timer & free up any MDI allocated
 *  memory.
 *
 * Returns : N/A
 */
void
MDI_DeRegister(mdi_t **mdi)
{
	int	i;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_DeRegister(0x%p)",
		    mdi);
#endif

	/* quick sanity check in case we got called back twice */
	if(mdi == NULL || *mdi == NULL) {
		return;
	}

	/*
	 * Remove the Callback Timer.
	 */
	if ((*mdi)->CallBackTimer != -1) {
		timer_delete((*mdi)->CallBackTimer);
	}

	/* Free the Per-PHY Data */
	for (i = 0; i < 31; i++) {
		if ((*mdi)->PhyData[i]) {
			free((*mdi)->PhyData[i]);
		}
	}

	/* Free the MDI Data */
	free(*mdi);
	*mdi = NULL;
}

/*
 * Function	: MDI_FindPhy()
 *
 * Description	:
 *	Search for a Phy at a particular index. Determine if one exists.
 *
 * Returns: MDI_SUCCESS if a phy is found
 *          else an error or failure message
 */
int
MDI_FindPhy(mdi_t *mdi, int PhyAddr)
{
	uint16_t	status;
	uint16_t	id1, id2;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_FindPhy(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31)	
		return (MDI_BADPARAM);

	mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	status = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);

	/* At least one bit should be a one or a zero */
	if (status == 0x0000 || status == 0xFFFF) {
		return (MDI_FAILURE);
	}

	/* Further sanity check */
	id1 = mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_1);
	id2 = mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_2);
	if (mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_1) != id1)
		return MDI_FAILURE;
	if (mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_2) != id2)
		return MDI_FAILURE;

	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_InitPhy()
 *
 * Description	:
 *	Allocates memory and Initialises the Phy and the PhyData Structure for
 *  this Phy.
 *  Reads the phy status register & tries to determine the phy's capabilities.
 *  If the phy supports autonegotiation, then starts the autoneg procedure. 
 *  Reads the phy's Id registers, & if it's a supported chipset then sets
 *  up the phy chip's specific GetMedia callbacks. 
 *
 *  Returns: MDI_SUCCESS
 *           or anything else is an error
 */
int
MDI_InitPhy (mdi_t *mdi, int PhyAddr)
{
	PhyData_t	*PhyData;
	uint32_t	PhyId;
	uint16_t	tmp;

#ifdef MDI_DEBUG
	nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_InitPhy(mdi=0x%p, PhyAddr0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31) {
		return (MDI_BADPARAM);
	}

	if ((PhyData = calloc(1, sizeof (PhyData_t))) == NULL) {
		return (MDI_NOMEM);
	}

	/* Store Capabilites + Allowed Media from Status Register. */
	MDI_GetMediaCapable(mdi, PhyAddr, &PhyData->MediaCapable);

	mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	PhyData->StatusReg = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	PhyData->CurrState = (PhyData->StatusReg & BMSR_LINK_STATUS) ?
	    MDI_LINK_UP : MDI_LINK_DOWN;

#ifdef MDI_DEBUG
	nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "Read of BMSR Register = 0x%04x",PhyData->StatusReg);
#endif

	/*
	 * If we can AutoNegotiate and the Partner can as well then
	 * go into AutoNegotiate mode and let the PHY handle it all.
	 * However, if we can AutoNegotiate (or not!) and the Partner
	 * can't, set the Speed but at Half Duplex (99.9% of hubs/cards).
	 */
	if (PhyData->StatusReg & BMSR_AN_ABILITY) {
		PhyData->Control = BMCR_AN_ENABLE;
	} else {
		/*
		 * O.K., we can't auto-negotiate.
		 * Default to Half Duplex, no way to tell if there is
		 * Full Duplex Capability on other side.
		 */
		tmp = PhyData->MediaCapable;
		if (tmp & MDI_100bT || tmp & MDI_100bT4) {
			PhyData->SetSpeed = 100;
			PhyData->Control |= BMCR_SPEED_100;
		} else if (tmp & MDI_10bT) {
			PhyData->SetSpeed = 10;
		} else if (tmp & MDI_1000bT || tmp & MDI_1000bX) {
			PhyData->SetSpeed = 1000;
			PhyData->Control |= BMCR_SPEED_1000;
		}
	}

	PhyId = (mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_1)) << 16;
	PhyId |= mdi->Read(mdi->handle, PhyAddr, MDI_PHYID_2);

	PhyData->VendorOUI = PHYID_VENDOR(PhyId);
	PhyData->Model = PHYID_MODEL(PhyId);
	PhyData->Rev = PHYID_REV(PhyId);

	switch(PhyData->VendorOUI) {
	    case BROADCOM:
			switch (PhyData->Model) {
				uint16_t	int_status;
				case BM5202:
					/* Setup the interrupt masking */
					int_status = 0;
					int_status |= (1 << 15);
					int_status |= (1 << 8);
					mdi->Write(mdi->handle, PhyAddr, 0x1A, int_status);

					PhyData->GetMedia = GetMedia_BM5202;
					PhyData->ResetComplete = ResetComplete_BM5202;
					PhyData->Desc = "Broadcom BM5202";
					break;
				default:
					PhyData->Desc = "Broadcom Generic";
					break;
			}
			break;

		case NATIONAL_SEMICONDUCTOR:
			switch (PhyData->Model) {
				case DP_83840:
					switch (PhyData->Rev) {
					    case DP_83840A:
							PhyData->GetMedia = GetMedia_DP83840A;
							PhyData->ResetComplete = ResetComplete_DP83840A;
							PhyData->Desc = "National SemiConductor DP83840A";
							break;
					    default:
							PhyData->ResetComplete = ResetComplete_DP83840A;
							PhyData->GetMedia = GetMedia_DP83840A;
							PhyData->Desc = "National SemiConductor DP83840";
							break;
						}
					break;
				case DP_83843:
					PhyData->GetMedia = GetMedia_DP83843;
					PhyData->Desc = "National SemiConductor DP83843";
					break;
				case DP_83620:
					/* DP83620 has the same PHYSTS register as DP83843 */
					PhyData->GetMedia = GetMedia_DP83843;
					PhyData->Desc = "National SemiConductor DP83620";
					break;
				default:
					PhyData->Desc = "Generic National SemiConductor";
					break;
			}
			break;
		case LEVEL_ONE:
			switch (PhyData->Model) {
				case LXT_9746:
					PhyData->GetMedia = GetMedia_LXT9746;
					PhyData->Desc = "Level One LXT-9746";
					break;
				default:
					PhyData->Desc = "Generic Level One";
					break;
			}
			break;
		case QUALITY_SEMICONDUCTOR:
			switch (PhyData->Model) {
				case QS6612_HUGH:
				case QS6612:
					PhyData->GetMedia = GetMedia_QS6612;
					PhyData->Desc = "Quality Semiconductor QS6612";
					break;
				default:
					PhyData->Desc = "Generic Quality SemiConductor";
					break;
			}
			break;
		case ICS:
			switch (PhyData->Model) {
				case	ICS1889:
					PhyData->Desc = "ICS 1889";
					break;
				case	ICS1890:
					PhyData->GetMedia = GetMedia_ICS1890;
					PhyData->ResetComplete = ResetComplete_ICS1890;

					switch (PhyData->Rev) {
						case INTERNAL:
							PhyData->Desc = "ICS 1890 (Internal)";
							break;
						case ALPHA_1890:
							PhyData->Desc = "ICS 1890 (Alpha)";
							break;
						case GEN_REL:
							PhyData->Desc = "ICS 1890 (Gen. Rel.)";
							break;
						case J_RELEASE:
							PhyData->Desc = "ICS 1890 (J+ Rel.)";
							break;
						default:
							PhyData->Desc = "ICS 1890 Generic";
							break;
					}
					break;
				default:
					PhyData->Desc = "Generic ICS PHY";
			}
			break;
		case	INTEL:
			switch (PhyData->Model) {
				case	I82555:
					PhyData->GetMedia = GetMedia_I82555;
					PhyData->ResetComplete = ResetComplete_I82555;
					switch (PhyData->Rev) {
						case	I82555_REV:
							PhyData->Desc = "INTEL 82555 (Rev 0)";
							break;
						default:
							PhyData->Desc = "INTEL 82555";
							break;
					}
					break;
				default:
					PhyData->Desc = "Unknown INTEL PHY";
			}
			break;
		case	DAVICOM:
			switch (PhyData->Model) {
				case	DM9101:
					PhyData->GetMedia = GetMedia_DM9101;
					PhyData->ResetComplete = ResetComplete_DM9101;
					switch (PhyData->Rev) {
						case	DM9101_REV:
							PhyData->Desc = "Davicom DM9101 (Rev 0)";
							break;
						case	DM9101_AREV:
							PhyData->Desc = "Davicom DM9101 (Rev 1)";
							break;
						default:
							PhyData->Desc = "Davicom DM9101";
							break;
					}
					break;
				default:
					PhyData->Desc = "Unknown Davicom PHY";
			}
			break;
		case	MYSON:
			switch (PhyData->Model) {
				case	MTD972:
					/* MDT972 is a clone of the DP83840A */
					PhyData->GetMedia = GetMedia_DP83840A;
					PhyData->ResetComplete = ResetComplete_DP83840A;
					PhyData->GetMedia = GetMedia_DP83840A;
					PhyData->Desc = "Myson MDT972";
					break;
				default:
					PhyData->Desc = "Unknown Myson PHY";
			}
			break;
		case	LSILOGIC:
			if (PhyData->Model == LSI80225) {
				PhyData->GetMedia = GetMedia_LSI80225;
				PhyData->Desc = "LSI Logic 80225";
			} else {
				PhyData->Desc = "Unknown LSI PHY";
			}
			break;

		case TDK:
			switch (PhyData->Model) {
				case TDK78Q2120:
					PhyData->Desc = "TDK 78Q2120";
					break;
				default:
					PhyData->Desc = "Unknown TDK PHY";
					break;
			}
			break;

		default:
			PhyData->Desc = "Generic PHY";
			break;
	}

	mdi->PhyData[PhyAddr] = PhyData;

	/* Inititally set SetAdvert to MediaCapable */
	mdi->PhyData[PhyAddr]->SetAdvert = PhyData->MediaCapable;

	MDI_SyncPhy(mdi, PhyAddr);
	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_GetLinkStatus()
 *
 * Description	:
 *	Reads the phy's BMSR register & gets the Status of the link on this phy.
 *
 * Returns: MDI_LINK_UP or MDI_LINK_DOWN
 *          or MDI_BADPARAM or MDI_LINK_UNKNOWN on error
 */
int
MDI_GetLinkStatus(mdi_t *mdi, int PhyAddr)
{
	uint16_t	Status = 0;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_GetLinkStatus(mdi=0x%p, PhyAddr=0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL) {
		return (MDI_BADPARAM);
	}

	mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	Status = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	if (Status == 0xFFFF || Status == 0x0000) {
		mdi->PhyData[PhyAddr]->CurrState = MDI_LINK_UNKNOWN;
		return (MDI_LINK_UNKNOWN);
	}
	mdi->PhyData[PhyAddr]->CurrState = (Status & BMSR_LINK_STATUS) ?
	    MDI_LINK_UP : MDI_LINK_DOWN;

	mdi->PhyData[PhyAddr]->StatusReg = Status;

	return ((int)(mdi->PhyData[PhyAddr]->CurrState));
}

/*
 * Function	: MDI_GetActiveMedia()
 *
 * Description	:
 *	Gets the Media which the Current Link, if any is at.
 *
 * Returns: MDI_LINK_UP with link type in *Media
 *          or MDI_LINK_DOWN 
 *          or MDI_BADPARAM
 *
 *          NOTE: MDI_LINK_UP does not mean that the link is up, it
 *                means that we recognize what media we are supposed
 *                to be set at etc, for the actual link status we should
 *                use MDI_GetLinkStatus
 */
int
MDI_GetActiveMedia (mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	ANae;
	int		Advert, PAdvert, i;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_GetActiveMedia(0x%p, 0x%x, 0x%p)",
		    mdi, PhyAddr, Media);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL) {
		return (MDI_BADPARAM);
	}

	*Media = 0;	/* WipeOut Media if nothing detected */

	if (!(mdi->PhyData[PhyAddr]->Control & BMCR_AN_ENABLE)) {
		/* User has Forced Settings */
		if (mdi->PhyData[PhyAddr]->SetSpeed == 1000) {
			if (mdi->PhyData[PhyAddr]->SetDuplex) {
				*Media = MDI_1000bTFD;
			} else {
				*Media = MDI_1000bT;
			}
		} else {
			if (mdi->PhyData[PhyAddr]->SetSpeed == 100) {
				if (mdi->PhyData[PhyAddr]->SetDuplex) {
					*Media = MDI_100bTFD;
				} else {
					*Media = MDI_100bT;
				}
			} else {
				if (mdi->PhyData[PhyAddr]->SetDuplex) {
					*Media = MDI_10bTFD;
				} else {
					*Media = MDI_10bT;
				}
			}
		}

		/* Don't Care if Up/Down, it is forced!!! */
		return (MDI_LINK_UP);
	}

	if (mdi->PhyData[PhyAddr]->VendorOUI == LSILOGIC) {
		mdi->Read (mdi->handle, PhyAddr, MDI_BMSR);
		ANae = mdi->Read (mdi->handle, PhyAddr, MDI_BMSR);
		if (!(ANae & BMSR_LINK_STATUS)) {
			return (MDI_LINK_DOWN);
		}
		if (!(ANae & BMSR_AN_COMPLETE)) {
			return (MDI_LINK_DOWN);
		}

		return (GetMedia_LSI80225 (mdi, PhyAddr, Media));
	}

	if (mdi->PhyData[PhyAddr]->StatusReg & BMSR_EXTENDED_CAP) {
		mdi->Read(mdi->handle, PhyAddr, MDI_ANAE);
		ANae = mdi->Read(mdi->handle, PhyAddr, MDI_ANAE);
		if (ANae & ANAE_PAR_DETECT_FAULT) {
			uint16_t MediaT[6][2]  = { {10  , 0},
						  {100 , 0},
						  {1000, 0},
						  {10  , 1},
						  {100 , 1},
						  {1000, 1} };
			uint16_t OldC = mdi->PhyData[PhyAddr]->Control;
			uint16_t OldSpeed = mdi->PhyData[PhyAddr]->SetSpeed;
			uint8_t	OldDup = mdi->PhyData[PhyAddr]->SetDuplex;
			uint16_t OldAd = mdi->PhyData[PhyAddr]->SetAdvert;

			/*
			 * Multiple Link Fault.
			 * O.K., The AutoNegotiation Engine is screwed and
			 * hasn't an got an Idea of the Link. So we attempt
			 * to force a setup. We Force 100bT, check the link..
			 * If it fails force 10bt check the link if it still
			 * fails. Who knows ?, maybe add FDuplex Support here.
			 */
			for (i = 0; i < 6; i++) {
				MDI_SetSpeedDuplex(mdi, PhyAddr,
				    MediaT[i][0], MediaT[i][1]);
				delay (10);
				if (MDI_GetLinkStatus(mdi, PhyAddr) ==
				    MDI_LINK_UP)
					break;
			}
			if (i == 6) {
				/* No Link Found, Restore.. */
				mdi->PhyData[PhyAddr]->Control = OldC;
				mdi->PhyData[PhyAddr]->SetSpeed = OldSpeed;
				mdi->PhyData[PhyAddr]->SetDuplex = OldDup;
				mdi->PhyData[PhyAddr]->SetAdvert = OldAd;
				return (MDI_LINK_DOWN);
			} else {
				switch(i) {
					case 0: *Media = MDI_10bT; break;
					case 1: *Media = MDI_100bT; break;
					case 2: *Media = MDI_1000bT; break;
					case 3: *Media = MDI_10bTFD; break;
					case 4: *Media = MDI_100bTFD; break;
					case 5: *Media = MDI_1000bTFD; break;
					default: *Media = MDI_UNKNOWN; break;
					}
				/* Don't Care if Up/Down, it is forced!!! */
				return (MDI_LINK_UP);
			}
		}
	}

	/* Is there a Link ? */
	if (MDI_GetLinkStatus(mdi, PhyAddr) != MDI_LINK_UP)
		return MDI_LINK_DOWN;

	if (MDI_GetPartnerAdvert(mdi, PhyAddr, &PAdvert) != MDI_SUCCESS)
		PAdvert = 0;

	if (mdi->PhyData[PhyAddr]->StatusReg & BMSR_EXTENDED_CAP &&
	    (PAdvert ||
	    (mdi->Read(mdi->handle, PhyAddr, MDI_ANAE) & ANAE_LP_AN_ABLE))) {
		if (MDI_GetAdvert(mdi, PhyAddr, &Advert) != MDI_SUCCESS)
			Advert = 0;
		Advert = Advert & PAdvert;

		/* Media priority is defined by Annex 28B.3 */
		if (Advert & MDI_1000bTFD)
			*Media = MDI_1000bTFD;
		else if (Advert & MDI_1000bT)
			*Media = MDI_1000bT;
		else if (Advert & MDI_100bT2FD)
			*Media = MDI_100bT2FD;
		else if (Advert & MDI_100bTFD)
			*Media = MDI_100bTFD;
		else if (Advert & MDI_100bT2)
			*Media = MDI_100bT2;
		else if (Advert & MDI_100bT4)
			*Media = MDI_100bT4;
		else if (Advert & MDI_100bT)
			*Media = MDI_100bT;
		else if (Advert & MDI_10bTFD)
			*Media = MDI_10bTFD;
		else if (Advert & MDI_10bT)
			*Media = MDI_10bT;

		if (*Media != 0)
			return (MDI_LINK_UP);
	}

	/* Go PHY Specific, if possible ! */
	if (mdi->PhyData[PhyAddr]->GetMedia) {
		return (mdi->PhyData[PhyAddr]->GetMedia(mdi, PhyAddr, Media));
	}

	*Media = MDI_UNKNOWN;
	return (MDI_LINK_UP);
}

/*
 *
 * Function	: MDI_SyncPhy()
 *
 * Description	:
 *	Sync the PHY by writing out the Preamble to it. The MDIWriteFunc
 *	provided should do this, so write the MDI_BMCR back out to it.
 *	Usually called after a RESET has happened so if a PHY needs special
 *	servicing after RESET, we do it here. by calling the specific
 *  reset & setAdvert routines.
 *
 * Returns: MDI_SUCCESS
 *          or MDI_BADPARM if invalid phy address
 */
int
MDI_SyncPhy(mdi_t *mdi, int PhyAddr)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_SyncPhy(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	/* Restores Previous Configuration */
	mdi->Write(mdi->handle, PhyAddr,
	    MDI_BMCR, mdi->PhyData[PhyAddr]->Control);

	if (mdi->PhyData[PhyAddr]->ResetComplete)
		mdi->PhyData[PhyAddr]->ResetComplete(mdi, PhyAddr);

	if (mdi->PhyData[PhyAddr]->SetAdvert)
		MDI_SetAdvert(mdi, PhyAddr, mdi->PhyData[PhyAddr]->SetAdvert);

	return (MDI_SUCCESS);
}

/*
 *
 * Function	: MDI_IsolatePhy()
 * Description	:
 *	Electrically Isolate the PHY.
 */
int
MDI_IsolatePhy(mdi_t *mdi, int PhyAddr)

{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_IsolatePhy(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->PhyData[PhyAddr]->Control |= BMCR_ISOLATE;
	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR,
	    mdi->PhyData[PhyAddr]->Control);

	/* Allow the PHY to Settle */
	delay (4);

	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_DeIsolatePhy()
 * Description	:
 *	Electrically DeIsolate the PHY.
 */
int
MDI_DeIsolatePhy(mdi_t *mdi, int PhyAddr)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_DeIsolate(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->PhyData[PhyAddr]->Control &= ~BMCR_ISOLATE;
	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR,
	    mdi->PhyData[PhyAddr]->Control);

	return (MDI_SUCCESS);
}

/*
 *
 * Function	: MDI_PowerdownPhy()

 * Description	:
 *	Power down the PHY.
 */
int
MDI_PowerdownPhy(mdi_t *mdi, int PhyAddr)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_PowerdownPhy(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->PhyData[PhyAddr]->Control |= BMCR_SLEEP;
	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR,
	    mdi->PhyData[PhyAddr]->Control);

	/* Allow the PHY to Settle */
	delay (4);

	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_PowerupPhy()
 * Description	:
 *	Power up the PHY.
 */
int
MDI_PowerupPhy(mdi_t *mdi, int PhyAddr)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_PowerupPhy(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->PhyData[PhyAddr]->Control &= ~BMCR_SLEEP;
	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR,
	    mdi->PhyData[PhyAddr]->Control);

	return (MDI_SUCCESS);
}
/*
 * Function	: MDI_ResetPhy()
 * Description	:
 *	Reset the PHY. By default, always WaitBusy, Poll for Reset Complete.
 *	If you get an interrupt when the PHY resets, then specify NoWait or
 *	IrqNoWait and call MDI_SyncPhy() when the reset is completed.
 */
int
MDI_ResetPhy(mdi_t *mdi, int PhyAddr, MDIWaitType Wait)
{
	uint8_t	i;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_ResetPhy(0x%p, 0x%x)", mdi, PhyAddr);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR, mdi->PhyData[PhyAddr]->Control
	    | BMCR_RESET);
	mdi->PhyData[PhyAddr]->CurrState = MDI_RESET_PHY;

	if (Wait == WaitBusy) {
		/* The longest a PHY should take to RESET is .5 Seconds */
		for (i = 0; i < 70; i++) {
			if (!(mdi->Read(mdi->handle, PhyAddr, MDI_BMCR) & BMCR_RESET))
				break;

			delay (10);
		}
		if (i == 70) 	/* Wow, Outdid the 802.3 Spec, Ouch! */
			return (MDI_FAILURE);

		mdi->PhyData[PhyAddr]->CurrState = MDI_LINK_UNKNOWN;
		MDI_SyncPhy(mdi, PhyAddr);
	}

	if (Wait == WaitBusy) {
		delay (100);		//PHY needs time to settle
		}

	return (MDI_SUCCESS);
}

/*
 *
 * Function	: MDI_SetSpeedDuplex()
 *
 * Description	:
 *	Set the Speed/Duplex the PHY is to operate at. AutoNegotiation will
 * 	be disabled. The interface link will be forced.
 *
 * Returns: MDI_LINK_UP or MDI_LINK_DOWN
 *          anything else is an unsupported or bad parameter
 *
 */
int
MDI_SetSpeedDuplex (mdi_t *mdi, int PhyAddr, int Speed, int Duplex)
{
	uint16_t	SMedia;
	uint16_t	Media [3][2] = {{MDI_10bT, MDI_10bTFD},
		 		{MDI_100bT, MDI_100bTFD},
				{MDI_1000bT, MDI_1000bTFD}};
	int			offset = 0;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_SetSpeedDuplex(0x%p, 0x%x, %d, %d)", mdi,
		    PhyAddr, Speed, Duplex);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL) {
		return (MDI_BADPARAM);
	}

	if ((Speed != 10 && Speed != 100 && Speed != 1000) || (Duplex != 0 && Duplex != 1)) {
		return (MDI_BADPARAM);
	}
	if (Speed != 10)
		offset = (Speed == 100) ? 1 : 2;

	SMedia = mdi->PhyData[PhyAddr]->MediaCapable;
//	if (!(SMedia & (Media[(Speed == 100) ? 1 : 0][(Duplex == 1) ? 1 : 0]))) {
	if (!(SMedia & (Media[offset][(Duplex == 1) ? 1 : 0]))) {
		return (MDI_UNSUPPORTED);
	}

	mdi->PhyData[PhyAddr]->Control &= ~(BMCR_AN_ENABLE | BMCR_SPEED_100 |
	    BMCR_SPEED_1000 | BMCR_FULL_DUPLEX); 

	mdi->PhyData[PhyAddr]->SetSpeed = Speed;
	mdi->PhyData[PhyAddr]->SetDuplex = Duplex;
	mdi->PhyData[PhyAddr]->SetAdvert =
	    (Media[offset][(Duplex == 1) ? 1 : 0]);

	if (Speed == 100) {
		mdi->PhyData[PhyAddr]->Control |= BMCR_SPEED_100;
		}
	else {
		if (Speed == 1000) {
			mdi->PhyData[PhyAddr]->Control |= BMCR_SPEED_1000;
			}
		}

	if (Duplex == 1) {
		mdi->PhyData[PhyAddr]->Control |= BMCR_FULL_DUPLEX;
	}

	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR,
	    mdi->PhyData[PhyAddr]->Control);

	/* Allow a little Settle Time */
	delay (40);

	return (MDI_GetLinkStatus(mdi, PhyAddr));
}

/*
 * Function	: MDI_SetPhyAdvert()
 *
 * Description	:
 *	Set the Media Advertisement to be used by the PHY. This can result
 *	in Re-negotiation taking place
 *
 * Returns: MDI_SUCCESS if advertisement is capable & sent
 *          MDI_INVALID_MEDIA or MDI_UNSUPPORTED if phy cannot force
 *          anything else is an error
 */
int
MDI_SetAdvert(mdi_t *mdi, int PhyAddr, int Advert)
{
	uint16_t	anar, bmsr, tmp16;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1,
		    "MDI_SetAdvert(0x%p, 0x%x, 0x%x)", mdi, PhyAddr, Advert);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	bmsr = mdi->PhyData[PhyAddr]->StatusReg;

	if (!(bmsr & BMSR_AN_ABILITY && bmsr & BMSR_EXTENDED_CAP))
		return MDI_UNSUPPORTED;

	/* Override advert... it was passed in on cmdline. */
	mdi->PhyData[PhyAddr]->SetAdvert = Advert;

	anar = mdi->Read(mdi->handle, PhyAddr, MDI_ANAR);

	anar &= ~ANAR_ADVERT_MSK;
	anar |= (Advert & 0x1f) << 5;
	anar |= Advert & (MDI_FLOW | MDI_FLOW_ASYM);

	if (MDI_MS_VALID(mdi->PhyData[PhyAddr]->MediaCapable)) {
		if (bmsr & BMSR_EXT_STATUS) {
			/* GMII */
			tmp16 = mdi->Read(mdi->handle, PhyAddr, MDI_MSCR);
			tmp16 &= ~(MSCR_ADV_1000bTFD | MSCR_ADV_1000bT);
			if (Advert & MDI_1000bTFD)
				tmp16 |= MSCR_ADV_1000bTFD;
			if (Advert & MDI_1000bT)
				tmp16 |= MSCR_ADV_1000bT;
			mdi->Write(mdi->handle, PhyAddr, MDI_MSCR, tmp16);
		} else if (mdi->PhyData[PhyAddr]->MediaCapable &
		    (MDI_100bT2 | MDI_100bT2FD)) {
			if (Advert & MDI_100bT2FD)
				anar |= (1<<11);
			if (Advert & MDI_100bT2)
				anar |= (1<<10);
		}
	}

	anar |= 1;	/* Assumes 802.3! */

	mdi->Write(mdi->handle, PhyAddr, MDI_ANAR, anar);

	return MDI_SUCCESS;
}

/*
 * Function	: MDI_GetAdvert()
 * Description	:
 *	Gets my Advertisement if there is one.
 */
int
MDI_GetAdvert(mdi_t *mdi, int PhyAddr, int *Advert)
{
	uint16_t	anar, bmsr, tmp16;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_GetAdvert(0x%p, 0x%x, 0x%p)", mdi, PhyAddr,
		    Advert);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	bmsr = mdi->PhyData[PhyAddr]->StatusReg;

	if (!(bmsr & BMSR_AN_ABILITY && bmsr & BMSR_EXTENDED_CAP)) {
		*Advert = 0;
		return (MDI_UNSUPPORTED);
	}

	anar = mdi->Read(mdi->handle, PhyAddr, MDI_ANAR);

	*Advert = (anar >> 5) & 0x1f;

	if (MDI_MS_VALID(mdi->PhyData[PhyAddr]->MediaCapable)) {
		if (bmsr & BMSR_EXT_STATUS) {
			/* GMII */
			tmp16 = mdi->Read(mdi->handle, PhyAddr, MDI_MSCR);
			if (tmp16 & (1<<9))
				*Advert |= MDI_1000bTFD;
			if (tmp16 & (1<<8))
				*Advert |= MDI_1000bT;
		} else if (mdi->PhyData[PhyAddr]->MediaCapable &
		    (MDI_100bT2 | MDI_100bT2FD)) {
			if (anar & (1<<11))
				*Advert |= MDI_100bT2FD;
			if (anar & (1<<10))
				*Advert |= MDI_100bT2;
		}
	}

	return MDI_SUCCESS;
}

/*
 * Function	: MDI_GetPartnerAdvert()
 * Description	:
 *	Gets the Link Partners Advertisement if there is one.
 */
int
MDI_GetPartnerAdvert(mdi_t *mdi, int PhyAddr, int *Advert)
{
	uint16_t	anlpar, bmsr, tmp16;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1,
		    "MDI_GetPartnerAdvert(0x%p, 0x%x, 0x%p)",
		    mdi, PhyAddr, Advert);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->PhyData[PhyAddr]->StatusReg =
	    mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	bmsr = mdi->PhyData[PhyAddr]->StatusReg;

	*Advert = 0;

	if (!(bmsr & BMSR_AN_COMPLETE))
		/* Link partners valued not valid 'til autoneg complete */
		return MDI_AUTONEG;

	if (!(bmsr & BMSR_AN_ABILITY && bmsr & BMSR_EXTENDED_CAP))
		return MDI_UNSUPPORTED;

	anlpar = mdi->Read(mdi->handle, PhyAddr, MDI_ANLPAR);

	*Advert = (anlpar >> 5) & 0x1f;

	if (MDI_MS_VALID(mdi->PhyData[PhyAddr]->MediaCapable)) {
		if (bmsr & BMSR_EXT_STATUS) {
			/* GMII */
			tmp16 = mdi->Read(mdi->handle, PhyAddr, MDI_MSSR);
			if (tmp16 & (1<<11))
				*Advert |= MDI_1000bTFD;
			if (tmp16 & (1<<10))
				*Advert |= MDI_1000bT;
		} else if (mdi->PhyData[PhyAddr]->MediaCapable &
		    (MDI_100bT2 | MDI_100bT2FD)) {
			/*
			 * TODO complete 100bT2 support by using next
			 * pages to figure out if link partner supports
			 * 100bT2.
			 */
		}
	}

	return MDI_SUCCESS;
}

/*
 * Function	: MDI_AutoNegotiate()
 * Description	:
 *	This starts an AutoNegotiation Cycle. You specify the MDIWaitType,
 *	(by Default - WaitBusy) where we poll until AutoNegotiation completes
 *	or else we can return immediately if you get an interrupt on
 *	Autonegotiation Complete.
 */
int
MDI_AutoNegotiate (mdi_t *mdi, int PhyAddr, int timeout)
{
	int	my_timeout = 0;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_AutoNegotiate(0x%p, 0x%x, 0x%x)", mdi,
		    PhyAddr, timeout);
#endif

	if (!mdi || PhyAddr < 0 || PhyAddr > 31 || mdi->PhyData[PhyAddr] == NULL)
		return (MDI_BADPARAM);

	mdi->PhyData[PhyAddr]->Control &= ~(BMCR_SPEED_100 | BMCR_SPEED_1000 | BMCR_FULL_DUPLEX);
	mdi->PhyData[PhyAddr]->Control |= BMCR_AN_ENABLE;

	/*
	 * if speed/duplex not specified on cmdline, all Media Types are now available again...
	 * otherwise, use what was specified on cmdline.
	 */
	MDI_SetAdvert(mdi, PhyAddr, mdi->PhyData[PhyAddr]->SetAdvert);

	mdi->Write(mdi->handle, PhyAddr, MDI_BMCR,
	    mdi->PhyData[PhyAddr]->Control | BMCR_RESTART_AN);
	mdi->PhyData[PhyAddr]->CurrState = MDI_AUTONEG;

	switch (timeout) {
		case	WaitBusy:
			my_timeout = 700;		// 7 Seconds
			break;
		case	NoWait:
			my_timeout = 0;
			break;
		default:
			my_timeout = timeout * 100;
			break;
	}

	if (my_timeout) {
		int i;

		/* Wait for 2 Seconds */
		for (i = 0; i < my_timeout; i++) {
			if (mdi->Read(mdi->handle, PhyAddr, MDI_BMSR) & BMSR_AN_COMPLETE) {
				mdi->PhyData[PhyAddr]->CurrState = MDI_LINK_UNKNOWN;
				return (MDI_SUCCESS);
				}

			delay (10);
			}

		/*
		 * We wait roughly upto 7 seconds, for quick update, however
		 * if it hasn't finished, don't busy wait longer, let the
		 * Monitor pick up the change....
		 */
		return (MDI_FAILURE);
	}
	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_GetCallBackpid()
 * Description	:
 *	Allows User get the pid of our CallBack Proxy.
 */
int
MDI_GetCallBackpid(mdi_t *mdi, pid_t *pid)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_GetCallBackpid(0x%p, 0x%p)", mdi, pid);
#endif

	if (!mdi || !mdi->CallBack)
		return (MDI_BADPARAM);

	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_EnableMonitor()
 * Description	:
 *	Sets Flag which allows the Phy Monitor to Callback into the driver.
 */
int
MDI_EnableMonitor(mdi_t *mdi, int LDownTest)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_EnableMonitor(0x%p)", mdi);
#endif

	if (!mdi || !mdi->CallBack)
		return (MDI_BADPARAM);

	mdi->DisableMonitor = 0;
	mdi->LDownTest = (LDownTest) ? 1 : 0;
	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_DisableMonitor()
 * Description	:
 *	Sets Flags to disable the Phy Monitor calling back into driver.
 */
int
MDI_DisableMonitor(mdi_t *mdi)
{
#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_DisableMonitor(0x%p)", mdi);
#endif

	if (!mdi)
		return (MDI_BADPARAM);

	mdi->DisableMonitor = 1;
	mdi->LDownTest = 0;
	return (MDI_SUCCESS);
}

/*
 * Function	: MDI_MonitorPhy()
 * Description	:
 *	Called from your SLOW Timer Irq Handler to check the link
 *	if the Link has changed, it will call your Callback to inform
 *	you!.
 */
void
MDI_MonitorPhy(mdi_t *mdi)
{
	PhyData_t	*Phy;
	uint16_t	Status;
	uint8_t		PhyAddr, OldState;

#ifdef	MDI_DEBUG
	if (MdiDebug & MDI_TRACE)
		nic_slogf(_SLOGC_NETWORK, _SLOG_DEBUG1, "MDI_MonitorPhy(0x%p)", mdi);
#endif

	if (!mdi || !mdi->CallBack || mdi->DisableMonitor)
		return;

	for (PhyAddr = 0; PhyAddr < 32; PhyAddr++) {
		if (mdi->PhyData[PhyAddr] != NULL) {
			Phy = mdi->PhyData[PhyAddr];

			switch (Phy->CurrState) {
			case MDI_RESET_PHY:
				if (Phy->Cnt >= 2) {
					/* Should have RESET by Now! */
					MDI_SyncPhy(mdi, PhyAddr);
					Phy->CurrState = MDI_LINK_DOWN;
					Phy->Cnt = 0;
				} else
					Phy->Cnt++;
				break;
			case MDI_AUTONEG:
				mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
				Status = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
				if (!(Status & BMSR_AN_COMPLETE) &&
				    !(Status & BMSR_LINK_STATUS)) {
					break;
				}
				Phy->CurrState = MDI_LINK_DOWN;
				Phy->Cnt = 0;
				/* Fallen to Here, AutoNegotiation Complete */
				/* Let LINK_UP / LINK_DOWN be determined */
			case MDI_LINK_UP:
			case MDI_LINK_DOWN:
			case MDI_LINK_UNKNOWN:
				mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
				Status = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
				if (Status == 0xFFFF || Status == 0x0000) {
					Phy->CurrState = MDI_RESET_PHY;
					Phy->Cnt = 0;
					MDI_ResetPhy(mdi, PhyAddr, NoWait);
				} else {
					int	Advert, PAdvert;

					if (MDI_GetAdvert(mdi, PhyAddr, &Advert) != MDI_SUCCESS)
						Advert = 0;
					if (MDI_GetPartnerAdvert(mdi, PhyAddr, &PAdvert) != MDI_SUCCESS)
						PAdvert = 0;
					Advert &= PAdvert;

					OldState = Phy->CurrState;
					Phy->CurrState =
					    (Status & BMSR_LINK_STATUS) ?
					    MDI_LINK_UP : MDI_LINK_DOWN;

					if (Advert != mdi->PhyData[PhyAddr]->CurAdvert || OldState != Phy->CurrState) {
						mdi->CallBack(mdi->handle, PhyAddr, Phy->CurrState);
						}
					mdi->PhyData[PhyAddr]->CurAdvert = Advert;

					if (Phy->CurrState == MDI_LINK_DOWN) {
					/*
					 * Link is Down. If down more than 2 runs through
					 * the Monitor, Start looking for a new Link.
					 */
					if (mdi->LDownTest) {
						Phy->Cnt = 0;
						MDI_AutoNegotiate(mdi, PhyAddr, NoWait);
						}
					} else {
						Phy->Cnt = 0;
					}
				}
				break;
			default:
				break;
			}
		}
	}

}
				
/*
 * Function	:  MDI_Autonegotiated_Active_Media()
 *
 * Description	: checks the mdi link status & determines the BEST
 *                autonegotiated type of link
 *
 * Returns: MDI_LINK_UP ,the media type placed into the media ptr. 
 *          else anything else is an error or link down
 */
int
MDI_Autonegotiated_Active_Media (mdi_t *mdi, int phyaddr, int *media)
{
	uint16_t	bmsr;
	uint16_t	anlpar;
	uint16_t	anar;
	uint16_t	fusion;
	int		i;

	if (!mdi || phyaddr < 0 || phyaddr > 31 || mdi->PhyData[phyaddr] == NULL) {
		return (MDI_BADPARAM);
	}

	*media = 0;	/* WipeOut Media if nothing detected */

	/*
	 * do we have an autonegotiated link ?
	 */
	bmsr = mdi->Read(mdi->handle, phyaddr, MDI_BMSR);
	if (!(bmsr & BMSR_LINK_STATUS) || !(bmsr & BMSR_AN_COMPLETE)) {
		return (MDI_LINK_DOWN);
	}

	/*
	 * the assumption is that both phys take the highest link that
	 * they both advertised, however ......... 
	 */
	anlpar = mdi->Read(mdi->handle, phyaddr, MDI_ANLPAR);
	if (!(anlpar & ANLPAR_ACKNOWLEDGE)) {	//This might not work on some PHYs!!
		return (MDI_LINK_DOWN);
	}

	/* read what we sent out ....... */
	anar = mdi->Read(mdi->handle, phyaddr, MDI_ANAR);

	/* bits 9,8,7,6,5 on anar & analpar     */
	/*      100T4,100bTFD,100bT,10bTFD,10bT */
	/* bits 15,14,13,12,11 on BMSR          */
	fusion = (anar & anlpar) >> 5;
	bmsr >>= 11;

	*media = MDI_UNKNOWN;
	for (i = 7; i >= 0; i--) {
		if (fusion & (1 << i) && bmsr & (1 << i)) {
			*media = (1 << i);
			return (MDI_LINK_UP);
		}
	}

	return (MDI_LINK_UP);
}

int
MDI_GetMediaCapable(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	bmsr, emsr;

	bmsr = mdi->Read(mdi->handle, PhyAddr, MDI_BMSR);
	emsr = mdi->Read(mdi->handle, PhyAddr, MDI_EMSR);

	if (bmsr == 0xffff)
		return MDI_FAILURE;

	*Media = bmsr >> 11 | ((bmsr >> 3) & (MDI_100bT2|MDI_100bT2FD));
	if (bmsr & BMSR_EXT_STATUS)
		/* GMII */
		*Media |= emsr & 0xf000;

	return MDI_SUCCESS;
}

/* National Semiconductor */
int
GetMedia_DP83840A(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, NS83840A_PAR);

	if (SecretStatus & NS83840A_DUPLEX_STAT) {
		if (SecretStatus & NS83840A_SPEED_10)
			*Media = MDI_10bTFD;
		else
			*Media = MDI_100bTFD;
	} else {
		if (SecretStatus & NS83840A_SPEED_10)
			*Media = MDI_10bT;
		else
			*Media = MDI_100bT;
	}
	return (MDI_LINK_UP);
}

void
ResetComplete_DP83840A(mdi_t *mdi, int PhyAddr)
{
	uint16_t tmp;

	/* See Errata .. */
	tmp =  mdi->Read(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xB);
	mdi->Write(mdi->handle, PhyAddr, MDI_VENDOR_BASE + 0xB, tmp | (1<<10) |
	    (1<<5));

	if (mdi->PhyData[PhyAddr]->SetAdvert)
		return;
	else
		MDI_SetAdvert(mdi, PhyAddr, mdi->PhyData[PhyAddr]->MediaCapable);
}

int
GetMedia_DP83843(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, NS83843_PHYSTS);

	if (SecretStatus & NS83843_DUPLEX) {
		if (SecretStatus & NS83843_SPEED_10)
			*Media = MDI_10bT;
		else
			*Media = MDI_100bT;
	} else {
		if (SecretStatus & NS83843_SPEED_10)
			*Media = MDI_10bTFD;
		else
			*Media = MDI_100bTFD;
	}
	return (MDI_LINK_UP);
}

/* Level One */
int
GetMedia_LXT9746(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, L9746_CHIP_STATUS);

	if (SecretStatus & L9746_DUPLEX_STAT) {
		if (!(SecretStatus & L9746_SPEED_100))
			*Media = MDI_10bTFD;
		else
			*Media = MDI_100bTFD;
	} else {
		if (!(SecretStatus & L9746_SPEED_100))
			*Media = MDI_10bT;
		else
			*Media = MDI_100bT;
	}
	return (MDI_LINK_UP);
}

/* Quality SemiConductor Inc. */
int
GetMedia_QS6612(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, QS6612_PHY_CONTROL);

	switch (QS6612_GET_MODE(SecretStatus)) {
		case QS6612_10bT:
			*Media = MDI_10bT;
			break;
		case QS6612_100bT:
			*Media = MDI_100bT;
			break;
		case QS6612_100bT4:
			*Media = MDI_100bT4;
			break;
		case QS6612_10bTFD:
			*Media = MDI_10bTFD;
			break;
		case QS6612_100bTFD:
			*Media = MDI_100bTFD;
			break;
		case QS6612_AUTONEG:
		case QS6612_ISOLATE:
		default:
			return (MDI_LINK_DOWN);
	}
	return (MDI_LINK_UP);
}

/* ICS Inc. */
int
GetMedia_ICS1890(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, ICS1890_QPOLL);

	if (SecretStatus & ICS1890_DUPLEX) {
		if (!(SecretStatus & ICS1890_SPEED_100))
			*Media = MDI_10bTFD;
		else
			*Media = MDI_100bTFD;
	} else {
		if (!(SecretStatus & ICS1890_SPEED_100))
			*Media = MDI_10bT;
		else
			*Media = MDI_100bT;
	}
	return (MDI_LINK_UP);
}

void
ResetComplete_ICS1890(mdi_t *mdi, int PhyAddr)
{
	/* Comes up Isolated if no link found !! */
	MDI_DeIsolatePhy(mdi, PhyAddr);
}

/* INTEL Inc. */
int
GetMedia_I82555(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, I82555_SCTRL);

	if (SecretStatus & I82555_DUPLEX) {
		if (!(SecretStatus & I82555_SPEED_100))
			*Media = MDI_10bTFD;
		else
			*Media = MDI_100bTFD;
	} else {
		if (!(SecretStatus & I82555_SPEED_100))
			*Media = MDI_10bT;
		else
			*Media = MDI_100bT;
	}
	return (MDI_LINK_UP);
}

void
ResetComplete_I82555(mdi_t *mdi, int PhyAddr)
{
}

/* Davicom Inc. */
int
GetMedia_DM9101(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	SecretStatus;

	SecretStatus = mdi->Read(mdi->handle, PhyAddr, DM_DSCSR);

	if (SecretStatus & DSCSR_100FDX)
		*Media = MDI_100bTFD;
	else if (SecretStatus & DSCSR_100TX)
		*Media = MDI_100bT;
	else if (SecretStatus & MDI_10bTFD)
		*Media = MDI_10bTFD;
	else 
		*Media = MDI_10bT;

	return (MDI_LINK_UP);
}

void ResetComplete_DM9101(mdi_t *mdi, int PhyAddr)
{
}


int GetMedia_BM5202(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	bm_status;

	bm_status = mdi->Read(mdi->handle, PhyAddr, 0x19);
	switch(bm_status & BM5202_SPEED_MASK) {
		case BM5202_10BT:
		    *Media = MDI_10bT;
		    break;
		case BM5202_10BTFDX:
		    *Media = MDI_10bTFD;
		    break;
		case BM5202_100BTX:
		case BM5202_100BT4:
		    *Media = MDI_100bT;
		    break;
		case BM5202_100BTXFDX:
		    *Media = MDI_100bTFD;
		    break;
		default:
		    *Media = MDI_10bTFD;
		    break;
	}

	if(bm_status & (1 << 2)) {
		return (MDI_LINK_UP);
	} else {
		return(MDI_LINK_DOWN);
	}
}

void
ResetComplete_BM5202(mdi_t *mdi, int PhyAddr)
{
	return;
}

/* LSI Logic */
int
GetMedia_LSI80225(mdi_t *mdi, int PhyAddr, int *Media)
{
	uint16_t	Status;

	mdi->Read(mdi->handle, PhyAddr, LSI_STATOUT);
	Status = mdi->Read(mdi->handle, PhyAddr, LSI_STATOUT);
	if (Status == 0xffff)
		return (MDI_LINK_DOWN);

	if ((Status & (LSI_100MB | LSI_FD)) == (LSI_100MB | LSI_FD))
		*Media = MDI_100bTFD;
	else if (Status & LSI_100MB)
		*Media = MDI_100bT;
	else if (Status & LSI_FD)
		*Media = MDI_10bTFD;
	else 
		*Media = MDI_10bT;

	return (MDI_LINK_UP);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/mdi.c $ $Rev: 905867 $")
#endif
