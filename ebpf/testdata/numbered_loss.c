#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
static SSL_CTX *ctx;
static SSL *ss[64];
static int fds[64], port, repetitions;
static pthread_t reader[2];
static int read_result[2];
static void connect_one(int i) {
 fds[i]=socket(AF_INET,SOCK_STREAM,0);
 struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};
 inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
 if(connect(fds[i],(void*)&a,sizeof(a))) exit(21);
 if(!ss[i]) ss[i]=SSL_new(ctx);
 SSL_set_fd(ss[i],fds[i]);
 if(SSL_connect(ss[i])!=1) exit(22);
}
static void send_one(int i,int ex) {
 char b[512]; memset(b,'a'+i%26,sizeof(b));
 int r; size_t n=0;
 if(ex) { r=SSL_write_ex(ss[i],b,sizeof(b),&n); if(r!=1||n!=sizeof(b)) exit(23); }
 else if(SSL_write(ss[i],b,sizeof(b))!=sizeof(b)) exit(24);
}
static void *burst(void *arg) { int i=(int)(long)arg; for(int n=0;n<repetitions;n++) send_one(i,0); return NULL; }
static void *read_one(void *arg) { int i=(int)(long)arg; char b[16]; read_result[i]=SSL_read(ss[0],b,1); return NULL; }
static void *churn_one(void *arg) { (void)arg; connect_one(0); send_one(0,0); SSL_free(ss[0]); close(fds[0]); ss[0]=NULL; return NULL; }
int main(int argc,char **argv) {
 signal(SIGPIPE,SIG_IGN); port=atoi(argv[1]);
 ctx=SSL_CTX_new(TLS_client_method()); SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
 puts("ready"); fflush(stdout);
 char line[128], op; int i,n;
 while(fgets(line,sizeof(line),stdin)) {
  i=n=0; sscanf(line,"%c %d %d",&op,&i,&n);
  if(op=='D') { pthread_t thread; pthread_create(&thread,NULL,churn_one,NULL); pthread_join(thread,NULL); puts("D ok"); }
  if(op=='N') { connect_one(i); printf("N %d %llu\n",i,(unsigned long long)ss[i]); }
  if(op=='W'||op=='E') { for(int j=0;j<n;j++)send_one(i,op=='E'); printf("%c ok\n",op); }
  if(op=='B') { pthread_t ts[64]; repetitions=n; for(int j=0;j<i;j++)pthread_create(&ts[j],NULL,burst,(void*)(long)j); for(int j=0;j<i;j++)pthread_join(ts[j],NULL); puts("B ok"); }
  if(op=='C') { int (*clear)(SSL*)=dlsym(RTLD_DEFAULT,"SSL_clear"); if(!clear)exit(28); SSL_set_shutdown(ss[i],SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN); if(clear(ss[i])!=1)exit(29); close(fds[i]); connect_one(i); printf("C %d %llu\n",i,(unsigned long long)ss[i]); }
  if(op=='F') { SSL_free(ss[i]); close(fds[i]); ss[i]=NULL; puts("F ok"); }
  if(op=='R') { unsigned long long old; sscanf(line,"R %d %llu",&i,&old); int tries; for(tries=0;tries<1000;tries++) {ss[i]=SSL_new(ctx); if((unsigned long long)ss[i]==old)break; SSL_free(ss[i]);} if(tries==1000)exit(25); connect_one(i);printf("R %d %llu %d\n",i,(unsigned long long)ss[i],tries+1); }
  if(op=='O') { pthread_create(&reader[0],NULL,read_one,(void*)0); puts("O ok"); }
  if(op=='Z') { char b; read_result[1]=SSL_read(ss[0],&b,-1);puts("Z ok"); }
  if(op=='J') { pthread_join(reader[0],NULL);printf("J %d %d\n",read_result[0],read_result[1]); }
  if(op=='V') { char b; size_t count=0; int ok=SSL_read_ex(ss[i],&b,1,&count); printf("V %d %zu\n",ok,count); }
  if(op=='T') { char b[512]; memset(b,'t',sizeof(b)); size_t count=0; int ok=SSL_write_ex2(ss[i],b,sizeof(b),0,&count); printf("T %d %zu\n",ok,count); }
  if(op=='K') printf("K %ld\n",BIO_get_ktls_send(SSL_get_wbio(ss[i])));
  if(op=='S') { char path[]="/tmp/proof-sendfile-XXXXXX", b[512]; memset(b,'s',sizeof(b)); int fd=mkstemp(path); if(fd<0)exit(26); unlink(path); if(write(fd,b,sizeof(b))!=sizeof(b))exit(27); long result=SSL_sendfile(ss[i],fd,0,sizeof(b),0); close(fd); printf("S %ld\n",result); }
  fflush(stdout);
 }
 return 0;
}
