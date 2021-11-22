#pragma warning( disable : 4996)

#include "windows.h"
#include <stdlib.h>
#include "stdio.h"
#include "stdint.h"
#include "pcap.h"

int DecodePcap(const char *filein, const char *fileout);

int main()
{
	if (__argc < 3)
	{
		printf("Usage: icsneolib-pcap <inputfile> <outputfile>\n");
		exit(0);
	}
	DecodePcap(__argv[1], __argv[2]);

	char command[MAX_PATH];
	sprintf(command, "notepad.exe %s", __argv[2]);
	WinExec(command, SW_SHOW);
}

#define DATA_ON_WIRE_DECODER_DEVELOPMENT
#ifdef DATA_ON_WIRE_DECODER_DEVELOPMENT
#pragma pack(push, 1)
struct IcsLongEthHdr
{
	uint8_t destMAC[6];		// 0..5
	uint8_t srcMAC[6];		// 6..11
	uint16_t Protocol;		// Should be 0xcab1	12..13  // Big endian
	uint32_t icsEthernetHeader; // 0xaaaa5555 OK	14..17	// Big endian
	uint16_t payloadSize;	// 18..19	little endian
	uint16_t packetNumber; // 20..21	little endian

						   // packetInfo Big endian
	uint8_t	reserved;			// 22
	uint8_t firstPiece : 1;		// 23.0
	uint8_t lastPiece : 1;		// 23.1
	uint8_t bufferHalfFull : 1;	// 23.2
	uint8_t padding : 4;		// 23.3..6
	uint8_t ProtocolVersion1 : 1;// 23.7

	uint8_t AA;		// 24			AA for some reason
	uint8_t B1;		// 25			((1 << 4) | (uint8_t)Network::NetID::Main51), // Packet size of 1 on NETID_MAIN51
	uint8_t Command; // 26		(uint8_t)Command::RequestSerialNumber a1
	uint8_t B3; // 27			Packetizer::ICSChecksum(requestPacket.payload)
	uint8_t Extra[76];
};

struct IcsCan11BitArb
{
	uint8_t ArbID_3_11;	// 0
	uint8_t ArbID_0_2; // 1
	int GetArbID() { return (ArbID_3_11 << 3) + (ArbID_0_2 >> 5); }
	//int GetArbID() { return (ArbID_3_11 << 8) + ArbID_0_2; } // This isn't what the code says, but it looks like it works
};

struct IcsCanPacket11 // 15 bytes
{
	uint8_t NetworkID : 4;		// Network::NetID::Main51  whatever that means  27
	uint8_t Size: 4;			// DLC
	uint16_t DescriptionID;		// big endian 28
	IcsCan11BitArb ArbID;		// 29
	uint8_t LengthNibble : 4;	// 30
	uint8_t statusNibble : 4;
	uint8_t data[8];			// 24..32
};

struct IcsCanPacket11Fd
{
	uint8_t NetworkID : 4;		// Network::NetID::Main51  whatever that means  18
	uint8_t Size: 4;
	uint16_t DescriptionID;		// big endian 19..20

	IcsCan11BitArb ArbID;		// 21..22
	uint8_t FDFrame = 0xF;		// 23
	uint8_t LengthNibble : 4;	// 24
	uint8_t statusNibble : 4;
	uint8_t data[64];			// 25..89
};

struct IcsCan29BitArb
{
	uint8_t ArbID_28_21;		// byte 0
	uint8_t ArbID_16_17:2;		// byte 1
	uint8_t Unused1:1;
	uint8_t b29:1;				// if 1, then extended
	uint8_t Unused2:1;
	uint8_t ArbID_18_20:3;
	uint8_t ArbID_8_15;			// byte 2
	uint8_t ArbID_0_7;			// byte 3

	int GetArbID() {
		return ArbID_0_7 + (ArbID_8_15 << 8) + (ArbID_28_21 << 21) + (ArbID_16_17 << 16) + (ArbID_18_20 << 18);
	}
};

struct IcsCanPacket29 // 29 bit
{
	uint8_t NetworkID : 4;		// byte 18.0..4 with Network::NetID::Main51  whatever that means		| 0
	uint8_t Size: 4;
	uint16_t DescriptionID;		// 19..20 big endian													| 1..2
	IcsCan29BitArb ArbID;		// 21..24																| 3..6
	uint8_t LengthNibble : 4;	// 25
	uint8_t statusNibble : 4;
	uint8_t data[8];			// 26
};

struct IcsCanPacket29Fd // 29 bit
{
	uint8_t NetworkID : 4;		// Network::NetID::Main51  whatever that means  18
	uint8_t Size: 4;
	uint16_t DescriptionID;		// 19..20 big endian 
	IcsCan29BitArb ArbID;		// 21..24
	uint8_t FDFrame = 0xF;		// 25
	uint8_t LengthNibble : 7;	// 26.0..6
	uint8_t BaudRateSwitch : 1; // 26.7
	uint8_t data[64];			// 27..91
};

#endif DATA_ON_WIRE_DECODER_DEVELOPMENT
#pragma pack(pop)


void packet_handler_ICS(FILE *fpout, UINT32 packet, const struct pcap_pkthdr *header, const u_char *pkt_data);

int DecodePcap(const char *filein, const char *fileout)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	int res;
	int packet = 1;

	FILE *fpout = fopen(fileout, "w+");
	if (fpout == NULL)
		return -1;

	/* Open the capture file */
	if ((fp = pcap_open_offline(filein,			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", filein);
		return -1;
	}

	/* Retrieve the packets from the file */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		packet_handler_ICS(fpout, packet, header, pkt_data);
		packet++;
		//if (packet > 10000)
		//	break;
		/* print pkt timestamp and pkt len, data
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
		for (i=1; (i < header->caplen + 1 ) ; i++)
		printf("%.2x ", pkt_data[i-1]);
		printf("\n");
		*/
	}	

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}

	pcap_close(fp);
	fclose(fpout);
	return 0;
}

enum Command : uint8_t {
	EnableNetworkCommunication = 0x07,
	EnableNetworkCommunicationEx = 0x08,
	RequestSerialNumber = 0xA1,
	GetMainVersion = 0xA3, // Previously known as RED_CMD_APP_VERSION_REQ
	SetSettings = 0xA4, // Previously known as RED_CMD_SET_BAUD_REQ, follow up with SaveSettings to write to EEPROM
						//GetSettings = 0xA5 // Previously known as RED_CMD_READ_BAUD_REQ, now unused
	SaveSettings = 0xA6,
	UpdateLEDState = 0xA7,
	SetDefaultSettings = 0xA8, // Follow up with SaveSettings to write to EEPROM
	GetSecondaryVersions = 0xA9, // Previously known as RED_CMD_PERIPHERALS_APP_VERSION_REQ, versions other than the main chip
	RequestStatusUpdate = 0xBC,
	ReadSettings = 0xC7, // Previously known as 3G_READ_SETTINGS_EX
	SetVBattMonitor = 0xDB, // Previously known as RED_CMD_CM_VBATT_MONITOR
	RequestBitSmash = 0xDC, // Previously known as RED_CMD_CM_BITSMASH
	GetVBattReq = 0xDF, // Previously known as RED_CMD_VBATT_REQUEST
	MiscControl = 0xE7,
	FlexRayControl = 0xF3
};


const char *icsCommandAsString(int cmd)
{
	switch (cmd)
	{
	case Command::EnableNetworkCommunication: return "EnableNetworkCommunication";
	case Command::EnableNetworkCommunicationEx: return "EnableNetworkCommunicationEx";
	case Command::RequestSerialNumber: return "RequestSerialNumber";
	case Command::GetMainVersion: return "GetMainVersion";
	case Command::SetSettings: return "SetSettings";
		//case Command::GetSettings: return "GetSettings";
	case Command::SaveSettings: return "SaveSettings";
	case Command::UpdateLEDState: return "UpdateLEDState";
	case Command::SetDefaultSettings: return "SetDefaultSettings";
	case Command::GetSecondaryVersions: return "GetSecondaryVersions";
	case Command::RequestStatusUpdate: return "RequestStatusUpdate";
	case Command::ReadSettings: return "ReadSettings";
	case Command::SetVBattMonitor: return "SetVBattMonitor";
	case Command::RequestBitSmash: return "RequestBitSmash";
	case Command::GetVBattReq: return "GetVBattReq";
	case Command::MiscControl: return "MiscControl";
	case Command::FlexRayControl: return "FlexRayCCommand";
	default:
		return "?";
	}
}

//int Breaks2[] = { 6, 12, 14, 18, 24, -1};
// Convert binary to hexidecimal, return number of bytes written
int BinaryToHexString(char *ptr1, const void *pData, int NumberOfBytes, int *Breaks)
{
	int i, j;
	char *ptr2 = ptr1;

	for (i = 0; i < NumberOfBytes; i++)
	{
		for (j = 0; Breaks[j] != -1; j++)
			if (i == Breaks[j])
			{
				ptr2 += sprintf(ptr2, " ");
				break;

			}
		ptr2 += sprintf(ptr2, "%02X", ((UINT8 *)pData)[i]);
	}

	return ptr2 - ptr1;
}

uint8_t CANFD_DLCToLength(uint8_t length)
{
	if (length < 8)
		return length;

	switch(length) {
	case 0x9:
		return 12;
	case 0xa:
		return 16;
	case 0xb:
		return 20;
	case 0xc:
		return 24;
	case 0xd:
		return 32;
	case 0xe:
		return 48;
	case 0xf:
		return 64;
	}
	return 0;
}
#define SWAP2(x) (((x & 0xFF00) >> 8) | ((x & 0xFF) << 8))

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler_ICS(FILE *fpout, UINT32 packet, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[80];
	time_t local_tv_sec;
	char line_to_write[1024], *ptr = line_to_write;
	static UINT64 TimeStart_usec = 0;
	BOOL bFirstTime = TRUE;
	int i;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	IcsLongEthHdr *pIcsEthHeader = (IcsLongEthHdr *)pkt_data;
	/* retrieve the position of the ip header */
	int Protocol = SWAP2(pIcsEthHeader->Protocol);
	if (Protocol != 0xcab1) // only CAB1
		return;

	/* print timestamp and length of the packet */
	if (bFirstTime)
	{
		bFirstTime = FALSE;
		TimeStart_usec = (UINT64)header->ts.tv_sec * 1000000 + header->ts.tv_usec;
	}

	UINT64 TimeSinceStart_usec = ((UINT64)header->ts.tv_sec * 1000000 + header->ts.tv_usec) - TimeStart_usec;
	//ptr += sprintf(line_to_write, "%d %d.%06d", packet, (int)(TimeSinceStart_usec/1000000), (int)(TimeSinceStart_usec % 1000000));

	ptr += sprintf(ptr, "Dst:");
	for (i = 0; i < 6; i++)
		ptr += sprintf(ptr, "%02x", pIcsEthHeader->destMAC[i]);

	ptr += sprintf(ptr, " Src:");
	for (i = 0; i < 6; i++)
		ptr += sprintf(ptr, "%02x", pIcsEthHeader->srcMAC[i]);

	ptr += sprintf(ptr, " Protocol:%X", SWAP2(pIcsEthHeader->Protocol));

	ptr += sprintf(ptr, " Frame Size:%X", header->len);
	int s = sizeof(IcsCanPacket11); // 14
	s = sizeof(IcsCanPacket29); // 16
	s = sizeof(IcsCanPacket11Fd); // 71
	s = sizeof(IcsCanPacket29Fd); // 73
	s = sizeof(IcsLongEthHdr);	//28

								/*ptr += sprintf(ptr, " Payload Size:%d", pIcsPacket->payloadSize);
								
								
								//	int offset = offsetof(IcsLongEthHdr, B0);
								//	ptr += sprintf(ptr, " MysteryByte:%d Data:", pIcsPacket->MysteryByte);
								*/
	ptr += sprintf(ptr, " packetNumber:%d", pIcsEthHeader->packetNumber);
	ptr += sprintf(ptr, " Command:%x(%s)", pIcsEthHeader->Command, icsCommandAsString(pIcsEthHeader->Command));
	//if (pIcsEthHeader->B1 == 0xF)
	if (pkt_data[35] == 0xF || pkt_data[37] == 0xF)
	{
		IcsCanPacket29Fd *pCan29Fd = (IcsCanPacket29Fd *)((uint8_t *)pkt_data + 30);
		if (pCan29Fd->ArbID.b29)
		{
			ptr += sprintf(ptr, " TX_EXT_FD_ID:%X Data:", pCan29Fd->ArbID.GetArbID()); // wrong. something is strange in canpacket.cpp
			int Breaks1[] = { 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, -1 };
			ptr += BinaryToHexString(ptr, pCan29Fd->data, CANFD_DLCToLength(pCan29Fd->LengthNibble), Breaks1);
		}
		else
		{
			IcsCanPacket11Fd *pCan11Fd = (IcsCanPacket11Fd *)((uint8_t *)pkt_data + 30);
			ptr += sprintf(ptr, " TX_STD_FD_ID:%X Data:", pCan11Fd->ArbID.GetArbID()); // wrong. something is strange in canpacket.cpp
			int Breaks1[] = { 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, -1 };
			ptr += BinaryToHexString(ptr, pCan11Fd->data, CANFD_DLCToLength(pCan11Fd->LengthNibble), Breaks1);
		}
	}
	else
	{
		IcsCanPacket29 *pCan29 = (IcsCanPacket29 *)((uint8_t *)pkt_data + 30);
		if (pCan29->ArbID.b29)
		{
			ptr += sprintf(ptr, " TX_EXT_ID:%X Data:", pCan29->ArbID.GetArbID()); // wrong. something is strange in canpacket.cpp
			int Breaks1[] = { 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, -1 };
			ptr += BinaryToHexString(ptr, pCan29->data, pCan29->LengthNibble, Breaks1);
		}
		else
		{
			IcsCanPacket11 *pCan11 = (IcsCanPacket11 *)((uint8_t *)pkt_data + 30);
			ptr += sprintf(ptr, " TX_STD_ID:%X Data:", pCan11->ArbID.GetArbID()); // wrong. something is strange in canpacket.cpp
			int Breaks1[] = { 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, -1 };
			ptr += BinaryToHexString(ptr, pCan11->data, pCan11->LengthNibble, Breaks1);
		}
	}
	ptr += sprintf(ptr, "\nFrame Dump:");
	int Breaks2[] = { 6, 12, 14, 18, 24, 27, -1};
	ptr += BinaryToHexString(ptr, pkt_data, header->caplen, Breaks2);
	fprintf(fpout, "\n%s\n", line_to_write);
}

