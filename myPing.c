/*
* Ping を実現するプログラム
* rootしか使えないので使用する際はsudoを使用
* 追加機能として日本語表示(-J),ICMPのヘッダ構造を示す(-A)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

//日本語入力のオプション
#define JP 0x01

//ICMP表示のオプション
#define AN 0x02

//プロセスID取得
pid_t pid;
int  static recvSuccess = 0,sequence = 0;

//Mutexの初期設定
pthread_mutex_t mutex;

//FQDN名を格納する
char *name;

//引数入力に関係する変数
int count = -1;
int packetsize = 56, ip_ttl = 64;
long pattern = 1;
int patternFlag = 0;
char *endptr;
int waitSec = 1;

//getaddrinfoの結果を格納する構造体
struct in_addr addr;

//取得時間を計測するための構造体
struct timeval tv;

//日本語表記のオプションを取得する
unsigned char option = 0x00;

//スレッドを使うための準備
struct ThreadArgs{
  int sockfd;  
};

//プロトタイプ宣言
void InterruptSignalHandler(int signalType);
void DisplayResults();
void JPDisplayResults();
unsigned short calc_checksum(int len, void *start);
int send_icmp_packet(int sendsock);
int recv_icmp_packet(int recvsock);
int SetSignal();
int GetOption(int argc, char *argv[]);
int headerChecker(int sockfd);
void *ThreadMain(void *arg);

int main(int argc,char *argv[]){
    int err;
    int sendsock,recvsock,sockfd =0;
    char hostname[256];
    pthread_t threadID;
    struct addrinfo hints,*res;
    struct ThreadArgs *threadArgs;
    
    if(argc == 1){
        fprintf(stdout,"usage:%s <IPaddr> [-c count][-i waitSec]\n\t[-s packetsize][-t ttl]\n",argv[0]);
    }
    //mutexの作成
    pthread_mutex_init( &mutex, NULL );
    
    strncpy(hostname,argv[1],256);
    name = hostname;
    //引数取得
    if(GetOption(argc, argv) < 0){
        fprintf(stdout,"Get Option error\n");
        return -1;
    }
    
    //FQDN名を解決
    memset(&hints,0,sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    err = getaddrinfo(hostname,NULL,&hints,&res);
    if(err !=0 || res ==NULL){
        fprintf(stdout,"Can't get IPaddr\n");
        return -1;
    }
    addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
    
    //プロセスIDを取得
    pid = getpid();
    
    //シグナル(割り込み処理)の準備
    if(SetSignal() < 0){
        fprintf(stdout,"SetSignal() error\n");
        return -1;
    }
    
    //送信用ソケットの準備
    sendsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sendsock < 0){
        perror("send socket() error\n");
        return -1;
    }
    
    //受信用ソケットの準備
    recvsock = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_IP));
    if(recvsock < 0){
        perror("recvsocket() error\n");
        return -1;
    }
    
    //-pが指定されているときのみ表示
    if(patternFlag == 1){
        fprintf(stdout,"PATTERN: 0x%x\n",(unsigned int)pattern);
    }
    
    //基本情報の表示
    fprintf(stdout,"MYPING %s(%s) %d bytes of data\n",name,inet_ntoa(addr),packetsize);
    
    //ICMPの送受信
    while(1){
        //ICMPの送信
        if(send_icmp_packet(sendsock) < 0){
            return -1;
        }
        
        //現在時刻を取得
        gettimeofday(&tv, NULL);
        
        //ICMPの受信
        if(recv_icmp_packet(recvsock) < 0){
            return -1;
        }
        
        //-Aオプションを使っているか
        if(option & AN){
            //スレッド使用の準備
            if((threadArgs = (struct ThreadArgs *) malloc(sizeof(struct ThreadArgs))) ==NULL){
                fprintf(stdout,"malloc() error");
                return -1;
            }
            //threadArgs = new ThreadArgs[memory];
            threadArgs -> sockfd = sockfd;
            
            if(pthread_create(&threadID, NULL, ThreadMain, (void *)threadArgs)!=0){
                perror("pthread_create() error");
                return -1;
            }
            free(threadArgs);
        }
        
        //送信の間隔を空ける
        sleep(waitSec);
        
        //-cが指定されているときのみ処理(指定した回数送受信)
        if((--count) == 0 && count !=-1){
            break;
        }
    }
    //-Jオプションが指定されているかどうかを判定
    if(option & JP){
        //日本語で結果表示
        JPDisplayResults();
    }else{
        //通常の結果表示
        DisplayResults();
    }
    //ソケットを閉じる
    close(sendsock);
    close(recvsock);
    //mutex開放
    pthread_mutex_destroy( &mutex );
    return 0;
}

//割り込み文字(Ctrl+C)が入力されたときの処理
void InterruptSignalHandler(int signalType){
    if(option &JP){
        JPDisplayResults(); 
    }else{
        DisplayResults();
    }
    //mutex開放
    pthread_mutex_destroy( &mutex );
    exit(1);
}

//通常(英語)の結果表示
void DisplayResults(){
    int loss = (100-(recvSuccess/sequence)*100);
    printf("\n--- %s ping statistics ---\n",name);
    printf("%d packets transmitted, %d received, %d %% loss\n",sequence, recvSuccess, loss);
}

//日本語での結果表示
void JPDisplayResults(){
    int loss = (100-(recvSuccess/sequence)*100);
    printf("\n--- %s ping 統計 ---\n",name);
    printf("送信パケット数 %d ,受信パケット数 %d ,パケット損失 %d %% \n",sequence, recvSuccess, loss);
}

//割り込み文字(Ctrl+C)に処理を追加する
//返し値 0:正常 -1:異常
int SetSignal(){
    struct sigaction handler;
    handler.sa_handler = InterruptSignalHandler;
    if(sigfillset(&handler.sa_mask) <0 ){
        perror("sigfillset() failed\n");
        return -1;
    }
    handler.sa_flags = 0;
    if(sigaction(SIGINT, &handler,0) <0){
        perror("sigaction() failed\n");
        return -1;
    }
    return 0;
}

//ICMPの送信
//返し値 0:正常 -1:異常
int send_icmp_packet(int sendsock){
    int err;
    int datalen = 0;
    struct sockaddr_in sendPacket;
    struct packet{
		struct iphdr ip;
		struct icmphdr icmp;
		char data[65499];
	}packet;
	
    //ICMPヘッダの設定
    memset(&packet,0,sizeof(packet));
    memset(&(packet.data), pattern ,packetsize);
    datalen = strlen(packet.data);
    packet.icmp.type = ICMP_ECHO;
    packet.icmp.un.echo.id = htons(pid);
    packet.icmp.un.echo.sequence =htons(++sequence);
    datalen += sizeof(struct icmphdr);
    packet.icmp.checksum = calc_checksum(datalen,&(packet.icmp));
    
    //IPヘッダの設定
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    datalen += sizeof(struct iphdr);
    packet.ip.tot_len = 0;
    packet.ip.id = 0;
    packet.ip.frag_off = htons(0x02 << 13);
    packet.ip.ttl = ip_ttl;
    packet.ip.protocol = IPPROTO_ICMP;
    packet.ip.daddr = *(uint32_t *)&addr;
    packet.ip.saddr = 0;
    packet.ip.check = 0;
        
    memset(&sendPacket, 0 , sizeof(struct sockaddr_in));
    sendPacket.sin_family = PF_INET;
    sendPacket.sin_addr = addr;
    err = sendto(sendsock, &packet, datalen, 0, (struct sockaddr *)&sendPacket, sizeof(sendPacket));
    if(err < 0){
        perror("sendto() error");
        return -1;
    }
    return 0;
}

//ICMPの受信
//返し値 0:正常 -1:異常
int recv_icmp_packet(int recvsock){
    int icmplen = 0;
    int len = 0;
    int usec = 0;
    unsigned short icmpid, icmpseq;
    fd_set readfd;
    double msec;
    char sip[16];
    char buf[ETHER_MAX_LEN];
    struct iphdr *ip;
    struct icmphdr *icmp;
    struct timeval now, tout;
    
    if(option & AN){
        pthread_mutex_lock( &mutex );
    }
    while(1){
        gettimeofday(&now,NULL);
        
        //タイムアウト
        if(now.tv_sec >= (tv.tv_sec +2)){
            perror("timeout\n");
            return -1;
        }
        //受信時間を取得する    
        FD_ZERO(&readfd);
        FD_SET(recvsock, &readfd);
        tout.tv_sec = 0;
        tout.tv_usec = 100000;
        if(select((recvsock+1),&readfd, NULL, NULL, &tout)<= 0){
            continue;
        }
        if(FD_ISSET(recvsock, &readfd)==0){
            continue;
        }
        memset(buf, 0, sizeof(buf));
        len = recv (recvsock,buf,sizeof(buf),0);
        if(len < 0){
            perror("recv() error");
            return -1;
        }
        gettimeofday(&now,NULL);
        ip = (struct iphdr *)(buf + sizeof(struct ether_header));
        
        //IPヘッダを確認
        if((ip->protocol != IPPROTO_ICMP) || (ip->saddr != addr.s_addr)){
            icmp = (struct icmphdr *)((char *)ip + sizeof(struct iphdr));
            icmpid = ntohs(icmp->un.echo.id);
            if(icmp->type == ICMP_TIME_EXCEEDED){
                sprintf(sip, "%s", inet_ntoa(*(struct in_addr *)&(ip->saddr)));
                fprintf(stdout,"From %s icmp_seq=%d Time to live exceeded\n",sip,sequence);
                return -1;
            }
            continue;
        }
        
        icmp = (struct icmphdr *)((char *)ip + sizeof(struct iphdr));
        icmpid = ntohs(icmp->un.echo.id);
        
        //ICMPヘッダを確認
        if((icmp->type != ICMP_ECHOREPLY) || (icmpid != pid)){
            continue;
        }
        ++recvSuccess;
        icmpseq = ntohs(icmp->un.echo.sequence);
        icmplen = ntohs(ip->tot_len) - sizeof(struct iphdr);
        sprintf(sip, "%s", inet_ntoa(*(struct in_addr *)&(ip->saddr)));
        usec = ((now.tv_sec)&0x03) * 1000000 + now.tv_usec;
        usec = usec - ((tv.tv_sec)&0x03) * 1000000 - tv.tv_usec;
        msec = (double)usec / 1000;
        
        //-Jオプションが指定されているかどうかを判定
        if(option & JP){
            fprintf(stdout, "%d バイト応答　送信元 %s: icmp_seq=%d ttl=%d 時間=%.3f ミリ秒\n", icmplen, sip, icmpseq, ip->ttl, msec);   
        }else{
            fprintf(stdout, "%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", icmplen, sip, icmpseq, ip->ttl, msec);
        }
        break;
        
    }
    if(option & AN){
        pthread_mutex_unlock( &mutex );
    }
    return 0;
}

//引数を取得する
//返し値 0:正常 -1:異常
int GetOption(int argc,char *argv[]){
    int results = 0;
    //オプションを識別する
    while((results = getopt(argc, argv, "c:i:p:s:t:JA")) != -1){
        switch(results){
            
            case 'c': //パケットを送る回数を指定
                count = atoi(optarg);
                if(count<=0){
                    fprintf(stdout, "invalid count \n");
                    return -1;
                }
                break;
            
            case 'i': //パケットを送信する間隔を指定
                waitSec = atoi(optarg);
                if(waitSec == 0){
                    fprintf(stdout,"too few second or input invalid\n");
                    return -1;
                }else if(waitSec > 1000){
                    fprintf(stdout,"too big second\n");
                    return -1;
                }
                break;
                
            case 's': //パケットサイズを指定
                packetsize = atoi(optarg);
                if(packetsize > 1432){
                    fprintf(stdout,"invalid packetsize please input 0~1432\n");
                    return -1;
                }
                break;
            
            case 'p': //パターンを指定 
                pattern = strtol(optarg,&endptr,16);
                patternFlag++;
                break;
            
            case 't': //TTL値を指定
                ip_ttl = atoi(optarg);
                if(ip_ttl < 1 || ip_ttl > 255){
                    fprintf(stdout,"ttl %d out of range\n",ip_ttl);
                    return -1;
                }
                break;
            
            case 'J': //日本語を指定
                option |= JP;
                break;
                
            case 'A': //ICMPのヘッダを表示
                option |= AN;
                break;
                
            default:
                fprintf(stdout,"usage:./myPing <IPaddr> [-c count][-i waitSec]\n\t[-s packetsize][-t ttl]\n");
                return -1;
                break;
        }
    }
    return 0;
}

//チェックサムを計算する
unsigned short calc_checksum(int len, void *start){
    unsigned short *p;
    unsigned long sum = 0;

    p = (unsigned short *)start;
    while(len > 1){
        sum += *p;
        p++;
        len -= sizeof(unsigned short);
    }
    if(len){
        sum += *(uint8_t *)p;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (unsigned short)(~sum & 0xffff);
}

//ICMPの構造を表示する
//返し値 0:正常 -1:異常
int headerChecker(int sockfd){
    
    unsigned char buf[65536];
    int len, i;
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0){
        perror("socket()");
        return -1;
    }
    len = recv(sockfd, buf,sizeof(buf), 0);
    if(len < 0){
        perror("recv()");
        return -1;
    }
    fprintf(stdout,"==packet of %d bytes==",len);
    for(i = 0; i <len ; i++){
        if(i % 16 == 0){
            fprintf(stdout,"\n");
        }
        fprintf(stdout,"%02x ",buf[i]);
    }
    fprintf(stdout,"\n\n");
    close(sockfd);
    return 0;
    
}

//スレッドのメインプログラム
void *ThreadMain(void *threadArgs){
    int sockfd;
    pthread_detach(pthread_self());
    
    sockfd = ((struct ThreadArgs *)threadArgs) -> sockfd;
    pthread_mutex_lock( &mutex );
    if(headerChecker(sockfd) < 0){
        exit(1);
    }
    pthread_mutex_unlock( &mutex );
    return NULL;
}