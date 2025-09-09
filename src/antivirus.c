#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/sha.h"
#include "openssl/md5.h"
#include <time.h>
#include <dirent.h>
#include <regex.h>
#include <sys/inotify.h>
#include <unistd.h>
#include "curl/curl.h"

#define BUFFER_SIZE 8192
#define EVENT_SIZE (1024*(sizeof(struct inotify_event)+16))

typedef enum Threats {REPORTED_SHA256_HASH,REPORTED_MD5_HASH,REPORTED_BITCOIN,REPORTED_VIRUS} thr_t;

char *thr[4] = {"REPORTED_SHA256_HASH","REPORTED_MD5_HASH","REPORTED_BITCOIN","REPORTED_VIRUS"};

char *Months[12] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

char *Bool[2] = {"False","True"};

char *Safety[2] = {"Malware","Safe"};

typedef struct FileNames{
  char *name;
  struct FileNames *next;
} Fnames;

typedef struct InfectedFiles{
  char *name;
  thr_t type;
  struct InfectedFiles *next;
} Ifiles;

typedef struct SuspiciousDomains{
  char *file;
  char *path;
  char *domain;
  int  exec;
  int  result;
  struct SuspiciousDomains *next;
} SDom;

typedef struct CallData{
  char *memory;
  size_t size;
} CD;

void listfiles(char *rootpath,int *nfiles,Fnames **head){
  char subpath[200];
  struct dirent *files;
  DIR *dir = opendir(rootpath);
  Fnames *temp,*counter;
  if(dir == NULL){
    temp = (Fnames*)malloc(sizeof(Fnames));
    temp->name = strdup(rootpath);
    temp->next=NULL;
    if(*head==NULL){
      *head=temp;
    }
    else{
      counter=*head;
      while(counter->next!=NULL){
        counter=counter->next;
      }
      counter->next=temp;
    }
    (*nfiles)++;
    return;
  }
  while((files = readdir(dir)) != NULL){
    if(strcmp(files->d_name,".")&&strcmp(files->d_name,"..")){
      strcpy(subpath,rootpath);
      strcat(subpath,"/");
      strcat(subpath,files->d_name);
      listfiles(subpath,nfiles,head);
    }
  }
  closedir(dir);
}

int f(int x,int a,int b,int key){
  return a*x*x+b*x+key;
}

int det(int mat[3][3]){
  int ans;
  ans = mat[0][0] * (mat[1][1] * mat[2][2] - mat[2][1]*mat[1][2]) - mat[0][1] * (mat[1][0] * mat[2][2] - mat[1][2]*mat[2][0]) + mat[0][2] * (mat[1][0] * mat[2][1] - mat[1][1]*mat[2][0]);
  return ans;
}

void findSol(int coeff[3][4],int *a,int *b,int *key){
  int d[3][3] = {{coeff[0][0],coeff[0][1],coeff[0][2]},{coeff[1][0],coeff[1][1],coeff[1][2]},{coeff[2][0],coeff[2][1],coeff[2][2]}};
  int d1[3][3] = {{coeff[0][3],coeff[0][1],coeff[0][2]},{coeff[1][3],coeff[1][1],coeff[1][2]},{coeff[2][3],coeff[2][1],coeff[2][2]}};
  int d2[3][3] = {{coeff[0][0],coeff[0][3],coeff[0][2]},{coeff[1][0],coeff[1][3],coeff[1][2]},{coeff[2][0],coeff[2][3],coeff[2][2]}};
  int d3[3][3] = {{coeff[0][0],coeff[0][1],coeff[0][3]},{coeff[1][0],coeff[1][1],coeff[1][3]},{coeff[2][0],coeff[2][1],coeff[2][3]}};
  int D = det(d);
  int D1 = det(d1);
  int D2 = det(d2);
  int D3 = det(d3);
  *a = D1/D;
  *b = D2/D;
  *key = D3/D;
}

size_t write_callback(void *ptr,size_t size,size_t nmemb, void *userdata){
  size_t realsize = size * nmemb;
  CD *mem = (CD*)userdata;
  mem->memory = realloc(mem->memory,mem->size+realsize+1);
  memcpy(&(mem->memory[mem->size]),ptr,realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

int main(int argc,char *argv[]){
  time_t date;
  unsigned char md5[] = {0x85,0x57,0x8c,0xd4,0x40,0x4c,0x6d,0x58,0x6c,0xd0,0xae,0x1b,0x36,0xc9,0x8a,0xca}; 
  unsigned char sha256[] = {0xd5,0x6d,0x67,0xf2,0xc4,0x34,0x11,0xd9,0x66,0x52,0x5b,0x32,0x50,0xbf,0xaa,0x1a,0x85,0xdb,0x34,0xbf,0x37,0x14,0x68,0xdf,0x1b,0x6a,0x98,0x82,0xfe,0xe7,0x88,0x49};
  char *wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
  char *rootfolder;
  Fnames *allfiles=NULL,*temp;
  Ifiles *infected=NULL;
  char signature[]= {0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff, 0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10};
  int i,nfiles=0,infiles=0;
  time(&date);
  struct tm tm = *localtime(&date);
  if(argc<3){
    printf("Too few arguments!\n");
    return 1;
  }
  if(!strcmp(argv[1],"scan")){
    rootfolder = argv[2];
    listfiles(rootfolder,&nfiles,&allfiles);
    printf("\n[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Scanning Directory %s\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,rootfolder);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Found %d files\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Searching...\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    while(allfiles!=NULL){
      FILE *fptr;
      char line[256];
      char byte[1];
      Ifiles *temp,*counter;
      int j=0,matching=0;
      unsigned char buffer1[BUFFER_SIZE];
      size_t bytes_read1;
      SHA256_CTX ctx1;
      unsigned char hash1[SHA256_DIGEST_LENGTH];
      unsigned char buffer2[BUFFER_SIZE];
      size_t bytes_read2;
      MD5_CTX ctx2;
      unsigned char hash2[MD5_DIGEST_LENGTH];
      fptr = fopen(allfiles->name,"r");
      if(fptr==NULL) printf("Cannot open file\n");
      while(fgets(line,256,fptr)){
        if(strstr(line,wallet)){
          temp=(Ifiles*)malloc(sizeof(Ifiles));
          temp->name=allfiles->name;
          temp->type=REPORTED_BITCOIN;
          temp->next=NULL;
          if(infected==NULL) infected=temp;
          else{
            counter=infected;
            while(counter->next!=NULL){
              counter=counter->next;
            }
            counter->next=temp;
          }
          infiles++;
        }
      }
      fclose(fptr);
      fptr = fopen(allfiles->name,"rb");
      if(fptr==NULL) printf("Cannot open file\n");
      while(fread(byte,sizeof(byte),1,fptr)){
	      if(byte[0]==signature[j]){
	        j++;
	      }
	      else{
	        j=0;
	      }
	      if(j==16){
	        temp=(Ifiles*)malloc(sizeof(Ifiles));
	        temp->name=allfiles->name;
	        temp->type=REPORTED_VIRUS;
	        temp->next=NULL;
	        if(infected==NULL) infected=temp;
	        else{
	          counter=infected;
	          while(counter->next!=NULL){
	            counter=counter->next;
	          }
	          counter->next=temp;
	        }
	        infiles++;
	        j=0;
	      }
      }
      fclose(fptr);
      fptr = fopen(allfiles->name,"rb");
      SHA256_Init(&ctx1);
      while((bytes_read1 = fread(buffer1,1,BUFFER_SIZE,fptr))>0){
	      SHA256_Update(&ctx1,buffer1,bytes_read1);
      }
      SHA256_Final(hash1,&ctx1);
      for(j=0;j<SHA256_DIGEST_LENGTH;j++){
        if(hash1[j]==sha256[j]){
	        matching++;
	      }
        else{
	        matching=0;
	      }
      }
      if(matching==32){
	      temp=(Ifiles*)malloc(sizeof(Ifiles));
	      temp->name=allfiles->name;
	      temp->type=REPORTED_SHA256_HASH;
	      temp->next=NULL;
	      if(infected==NULL) infected=temp;
	      else{
	        counter=infected;
	        while(counter->next!=NULL){
	          counter=counter->next;
	        }
	        counter->next=temp;
	      }
	      infiles++;
      }
      fclose(fptr);
      fptr=fopen(allfiles->name,"rb");
      MD5_Init(&ctx2);
      while((bytes_read2=fread(buffer2,1,BUFFER_SIZE,fptr))>0){
	      MD5_Update(&ctx2,buffer2,bytes_read2);
      }
      MD5_Final(hash2,&ctx2);
      matching=0;
      for(j=0;j<MD5_DIGEST_LENGTH;j++){
	      if(hash2[j]==md5[j]){
	        matching++;
	      }
	      else{
	        matching=0;
	      }
      }
      if(matching==16){
	      temp=(Ifiles*)malloc(sizeof(Ifiles));
	      temp->name=allfiles->name;
	      temp->type=REPORTED_MD5_HASH;
	      temp->next=NULL;
	      if(infected==NULL) infected=temp;
	      else{
	        counter=infected;
	        while(counter->next!=NULL){
      	    counter=counter->next;
	        }
	        counter->next=temp;
	      }
	      infiles++;
      }
      fclose(fptr);
      allfiles=allfiles->next;
    }
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Operation Finished\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Processed %d files. ",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    printf("\033[0;31m");
    printf("Found %d infected\n\n",infiles);
    printf("\033[0m");
    while(infected!=NULL){
      printf("%s:%s\n",infected->name,thr[infected->type]);
      infected=infected->next;
    }
  }
  else if(!strcmp(argv[1],"inspect")){
    SDom *domains=NULL, *temp;
    rootfolder = argv[2];
    listfiles(rootfolder,&nfiles,&allfiles);
    printf("\n[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Scanning Directory %s\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,rootfolder);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Found %d files\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Searching...\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    regex_t regx;
    int value;
    value = regcomp(&regx,"([:\\./A-Za-z]*\\.com[/A-Za-z]*)",REG_EXTENDED);
    if(value!=0) printf("Compilation Error!\n");
    while(allfiles!=NULL){
      FILE *fptr;
      char line[256];
      fptr = fopen(allfiles->name,"r");
      if (fptr==NULL) printf("Cannot open file\n");
      while(fgets(line,256,fptr)){
	      regmatch_t match[1];
	      value = regexec(&regx,line,1,match,0);
	      if(value==0){
	        int  match_start = match[0].rm_so;
	        int  match_end = match[0].rm_eo;
	        int match_len = match_end-match_start;
	        char *match_str = (char*)malloc(sizeof(char)*(match_len+1));
	        strncpy(match_str,line + match_start,match_len);
	        match_str[match_len] = '\0';
	        char *file,*path,*ssc;
	        int l=0,len=0;
	        file = allfiles->name;
	        ssc = strstr(file,"/");
	        while(ssc){
	          l=strlen(ssc)+1;
	          file = &file[strlen(file)-l+2];
	          ssc = strstr(file,"/");
	        }
	        len = strlen(allfiles->name)-strlen(file);
	        path=(char*)malloc(sizeof(char)*(len+1));
	        strncpy(path,allfiles->name,len);
	        path[len]='\0';
	        CURL *curl;
	        CURLcode res;
	        char *domainname;
	        if(strstr(match_str,"https")){
	          domainname = (char*)malloc(sizeof(char)*match_len-8);
	          strncpy(domainname,match_str+8,match_len-8);
	          domainname[match_len-8]='\0';
	        }
	        else if(strstr(match_str,"http")){
	          domainname = (char*)malloc(sizeof(char)*match_len-7);
	          strncpy(domainname,match_str+7,match_len-7);
	          domainname[match_len-7]='\0';
	        }
	        else{
	          domainname = (char*)malloc(sizeof(char)*match_len);
	          strncpy(domainname,match_str,match_len);
  	        domainname[match_len]='\0';
	        }
	        char request[128] = "https://family.cloudflare-dns.com/dns-query?name=";
	        CD chunk;
	        char safety;
	        chunk.memory = malloc(1);
	        chunk.size = 0;
	        struct curl_slist *headers = NULL;
	        headers = curl_slist_append(headers,"accept: application/dns-json");
	        strcat(request,domainname);
	        curl = curl_easy_init();
	        curl_easy_setopt(curl,CURLOPT_URL,request);
	        curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION, write_callback);
	        curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
	        curl_easy_setopt(curl,CURLOPT_WRITEDATA, (void*)&chunk);
	        res = curl_easy_perform(curl);
	        safety = chunk.memory[10];
	        temp=(SDom*)malloc(sizeof(SDom));
	        temp->file=file;
	        temp->path=path;
	        temp->domain=match_str;
	        temp->exec=0;
	        if(safety=='0') temp->result=0;
	        else temp->result=1;
	        temp->next=NULL;
	        if(domains==NULL) domains=temp;
	        else{
	          SDom *counter;
	          counter=domains;
	          while(counter->next!=NULL){
	            counter=counter->next;
	          }
	          counter->next=temp;
	        }
	        free(chunk.memory);
	        curl_slist_free_all(headers);
	        curl_easy_cleanup(curl);
	      }
      }
      fclose(fptr);
      allfiles=allfiles->next;
    }
    regfree(&regx);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Operation Finished\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Processed %d files.\n\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    printf("|  FILE          |  PATH                 |  DOMAIN          |  EXECUTABLE  |  RESULT  |\n");
    printf("============================================================================================\n");
    while(domains!=NULL){
      printf("|  %s  |  %s  |  %s  |  %s  ",domains->file,domains->path,domains->domain,Bool[domains->exec]);
      if(domains->result){
	      printf("|  ");
	      printf("\033[0;32m");
	      printf("%s",Safety[domains->result]);
	      printf("\033[0m");
	      printf("  |\n");
      }
      else{
	      printf("|  ");
	      printf("\033[0;31m");
	      printf("%s",Safety[domains->result]);
	      printf("\033[0m");
	      printf("  |\n");
      }
      domains=domains->next;
    }
  }
  else if(!strcmp(argv[1],"monitor")){
    int notif,calls;
    char buffer[EVENT_SIZE];
    ssize_t len;
    off_t lpos = 0;
    char *name,*pname;
    int status=0;
    rootfolder = argv[2];
    printf("\n[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Monitoring Directory %s\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,rootfolder);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Waiting for events...\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    notif = inotify_init();
    if(notif<0) printf("Error at creating notifications!\n");
    calls = inotify_add_watch(notif,rootfolder,IN_CREATE | IN_DELETE | IN_MODIFY | IN_ACCESS | IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
    if(calls<0) printf("Error at creating watching\n");
    while(1){
      len = read(notif,buffer+lpos,sizeof(buffer)-lpos);
      if(len<0) printf("Error reading\n");
      lpos = 0;
      while(lpos < len){
	      struct inotify_event *event = (struct inotify_event *)(buffer+lpos);
	      if(event->wd == calls && event->len > 0){
	        if(event->mask & IN_CREATE) {
	          printf("File %s was created\n",event->name);
	          if(status==1&&strstr(event->name,name)!=NULL){
	            pname=strdup(event->name);
	            status=2;
	          }
	        }
	        else if(event->mask & IN_DELETE) {
	          printf("File %s was deleted from watched directory\n",event->name);
	          if(status==4&&strcmp(event->name,name)==0){
	            printf("\033[0;31m");
	            printf(" [WARN] Ransomware attack detected on file %s\n",name);
	            printf("\033[0m");
	          }
	        }
	        else if(event->mask & IN_MODIFY) {
	          printf("File %s was modified\n",event->name);
	          if(status==2&&strcmp(event->name,pname)==0){
	            status=3;
	          }
	        }
	        else if(event->mask & IN_ACCESS) {
	          printf("File %s was accessed\n",event->name);
	          name = strdup(event->name);
	          status =1;
	        }
	        else if(event->mask & IN_OPEN) {
	          printf("File %s was opened\n",event->name);
	        }
	        else if(event->mask & IN_CLOSE_WRITE) {
	          printf("File %s that opened for writing was closed\n",event->name);
	          if(status==3&&strcmp(event->name,pname)==0){
	            status=4;
	          }
	        }
	        else if(event->mask & IN_CLOSE_NOWRITE) {
	          printf("FIle %s that was not opened for writing was closed\n",event->name);
	        }
	      }
	      lpos += sizeof(struct inotify_event) + event->len;
      }
      usleep(200000);
    }
    close(calls);
    close(notif);
  }
  else if(!strcmp(argv[1],"slice")){
    int key,k=3,a,b,i;
    key = atoi(argv[2]);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Generating shares for key '%d'\n\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,key);
    srand((unsigned) time(&date));
    a=rand() % (1000+1);
    b=rand() % (1000+1);
    for(i=1;i<=10;i++){
      printf("(%d, %d)\n",i,f(i,a,b,key));
    }
  }
  else if(!strcmp(argv[1],"unlock")){
    if(argc<5){
      printf("Unauthorized Access!Shutting Down...\n");
      return 1;
    }
    int index,i,j,a=0,b=0,key=0;
    char *share;
    int shares[10];
    int sol[3][4];
    for(i=0;i<10;i++){
      shares[i]=0;
    }
    i=2;
    while(i<argc){
      share = strtok(argv[i],",");
      index=atoi(share);
      share=strtok(NULL,",");
      shares[index]=atoi(share);
      i++;
    }
    for(i=0;i<3;i++){
      for(j=0;j<4;j++){
	      sol[i][j]=0;
      }
    }
    j=0;
    for(i=0;i<10;i++){
      if(shares[i]!=0){
	      if(sol[j][0]!=0) j++;
	      if(j>2) break;
	      sol[j][0]=i*i;
	      sol[j][1]=i;
	      sol[j][2]=1;
        sol[j][3]=shares[i];
      }
    }
    findSol(sol,&a,&b,&key);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Received %d different shares \n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,argc-2);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Computed that a=%d and b=%d \n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,a,b);
    time(&date);
    tm = *localtime(&date);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Encryption key is: ",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    printf("\033[0;34m");
    printf("%d\n",key);
    printf("\033[0m");
  }
  else{
    printf("Error mode not supported!\n");
  }
  return 0;
}
