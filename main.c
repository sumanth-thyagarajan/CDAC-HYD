#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<libxml/parser.h>


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	/* file for storing the info about the packets */
	FILE *fp=fopen("packetfile.txt","a");
	char from1[]="From: ";
	char to1[]="To: ";
	char cr[]="\n";
	char Proto[]="Protocol: TCP";
	char srcp[]="Src port: ";
	char dstp[]="Dst port: ";
	char sport[64];
	char dport[64];
	/*opening xml file for checking the port id*/
	
	FILE *xm=fopen("scan.nmap.xml","r");
	int size_xm,xmd,j=0;
	char *xmlcontent;
	fseek(xm,0,SEEK_END);
	size_xm=ftell(xm);
	fseek(xm,0,SEEK_SET);
	//printf("\n\nsize=%d\n\n",size_xm);
	xmlcontent=(char *)malloc(size_xm*2);
	getchar();
	system("clear");
	xmd=fgetc(xm);
	while(xmd!=EOF)
	{
		//printf("%c",xmd);
		*xmlcontent=(char)xmd;
		xmlcontent++;
		xmd=fgetc(xm);
		j++;	
	}
	*xmlcontent='\0';
	for(int f=j;j>=0;j--)
		xmlcontent--;
	//printf("\n\n the content of the xml fil doiiiii%s",xmlcontent);
	
	/*done converting the content of the file to char array */

	/* size of the packet */
	int size_ip;
	int size_tcp;
	int size_payload;
	int i=0;	
	printf("\n\n*****************************************************************\n\n");
	printf("\nPacket number [%d] , length of the packet is %d\n\n",count++,header->len);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}


	/*checking for the source and destination port print source and destination IP addresses */
	
	char src_dst[]="portid=\"";
	char cts[]="\"";
	printf("\n       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));


	/* determine protocol */	

	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			//break;
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			//break;
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			//break;
			return;
		default:
			printf("   Protocol: unknown\n");
			//break;
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
//	printf("")

	/*writing ports to the file*/
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	sprintf(sport,"%d",ntohs(tcp->th_sport));
	strcat(src_dst,sport);
	strcat(src_dst,cts);
	//printf("\n\nport ehhhh%s",src_dst);
	char *pointer;
	pointer=strstr(xmlcontent,src_dst);
	char my_ip[]="10.244.1.238";
	int flag=0;		
	if(pointer==NULL)
	{
		if(strcmp(inet_ntoa(ip->ip_src),my_ip)==0)
		{
		flag=1;	
		fputs(from1,fp);
		fputs(inet_ntoa(ip->ip_src),fp);
		fputs(cr,fp);
		fputs(to1,fp);
		fputs(inet_ntoa(ip->ip_dst),fp);
		fputs(cr,fp);	
		fputs(srcp,fp);
		fputs(sport,fp);
		fputs(cr,fp);
		//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
		fputs(dstp,fp);
		sprintf(dport,"%d",ntohs(tcp->th_dport));
		fputs(dport,fp);
		fputs(cr,fp);	
		fputs(cr,fp);	

		}		
	}	
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	sprintf(dport,"%d",ntohs(tcp->th_dport));
	strcpy(src_dst,"portid=\"");
	strcat(src_dst,dport);
	strcat(src_dst,cts);	
	//printf("\n\nport ehhhh  %s",src_dst);
	pointer=strstr(xmlcontent,src_dst);	
	//printf("\n\n %s",xmlcontent);	
	if(pointer==NULL)	
	{
		//printf("\n\n try me");
		if(strcmp(inet_ntoa(ip->ip_dst),my_ip)==0)
		{
			flag=2;
			fputs(from1,fp);
			fputs(inet_ntoa(ip->ip_src),fp);
			fputs(cr,fp);
			fputs(to1,fp);
			fputs(inet_ntoa(ip->ip_dst),fp);
			fputs(cr,fp);	
			fputs(srcp,fp);
			fputs(sport,fp);
			fputs(cr,fp);
			//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
			fputs(dstp,fp);
			sprintf(dport,"%d",ntohs(tcp->th_dport));
			fputs(dport,fp);
			fputs(cr,fp);	
			fputs(cr,fp);	
		}			
	}	
	if(flag==1)
		printf("\n we are sending the packets:");
	else if(flag==2)
		printf("\n we are recieving the packets");
			
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
		
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	fclose(fp);
	fclose(xm);
return;
}

/*main*/

int main(int argc,char *argv[])
{
	/* declartions and initialisation for pcap programming */
	char filter[]="tcp";
	int num=10;
	char *dev,errbuf[PCAP_ERRBUF_SIZE];
	int i=0;
	pcap_if_t *alldevs,*d; 
	char devname[64];
	bpf_u_int32 net;
	bpf_u_int32 mask;	
	pcap_t *handle;
	struct bpf_program fp;
	FILE *Fp=fopen("packetfile.txt","r");
	/*pcap output file */
	FILE *pcapfile;

	/* declarations and intialisation for file read */
	
	FILE *xmlfile=fopen("/home/sumanth/scan.nmap.xml","r");
	int xmlread,packetread;
	printf("\n the content of the xml file is  :  \n\n");
	xmlread=fgetc(xmlfile);
	//printf("%c",xmlread);
	while(xmlread!=EOF)
	{
			printf("%c",xmlread);
			xmlread=fgetc(xmlfile);
	}
	getchar();
	system("clear");
	/*list of all interfaces and devices present */


	printf("\n the list all device that are present : \n");
	if(pcap_findalldevs(&alldevs,errbuf)==-1)
	{
		fprintf(stderr,"the device is not available");
		exit(1);
	}
	for(d=alldevs;d;d=d->next)
	{
		printf("\n%d. %s\tflags: %u\t",++i,d->name,d->flags);
		if(d->description)
			printf("{%s}",d->description);
		else
			printf("{description not available}");
	}



	/*asking user to enter the name of the interface to sniff*/
	
	printf("\n\n enter the interface name to perform sniffing : ");
	scanf("%s",devname);
	dev=devname;
	printf("\n the interface u want to sniff is [ %s ] :\n",dev);	


	
	/*checking and opening of the device */
	
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1)
	{
		printf("\n interface is not available : %s\n",errbuf);
		exit(1);
	}
	
	handle=pcap_open_live(dev,SNAP_LEN,0,1000,errbuf);
	if(handle==NULL)
	{
		printf("\n packet is captured do to %s : ",errbuf);
		exit(1);
	}
	else
		printf("\n capturing packets : \n");
	
	/*asking for filter type */
	
	printf("\n the filter type : TCP");
	//scanf("%s",filter);	

	/*compile bpf filter and setfilter */
	
	if(pcap_compile(handle,&fp,filter,0,net)==-1)
	{
		printf("\n error in pcap_compile :");
		exit(0);
	}
	if(pcap_setfilter(handle,&fp)==-1)
	{
		printf("\n error in pcap_setfilter : ");
		exit(0);
	}
	
	/*number of packets captured*/
	
	pcap_loop(handle,num,callback,NULL);
	pcap_freecode(&fp);
	pcap_close(handle);	
	printf("\n done sniffing :\n");
	printf("\n press enter continue");
	getchar();
	system("clear");
	/*reading the port details file*/ 	
	printf("\n the content of the packet file is  :  \n\n");
	packetread=fgetc(Fp);
	while(packetread!=EOF)
	{
			printf("%c",packetread);
			packetread=fgetc(Fp);
	}
	fclose(Fp);
	printf("\n press enter continue");
	getchar();
	

return 0;	
}
