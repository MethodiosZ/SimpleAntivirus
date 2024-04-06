#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "openssl"
#include <time.h>
#include <dirent.h>

typedef enum Threats {REPORTED_SHA256_HASH,REPORTED_MD5_HASH,REPORTED_BITCOIN,REPORTED_VIRUS} thr_t;

char *thr[4] = {"REPORTED_SHA256_HASH","REPORTED_MD5_HASH","REPORTED_BITCOIN","REPORTED_VIRUS"};

char *Months[12] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

typedef struct FileNames{
  char *name;
  struct FileNames *next;
} Fnames;

typedef struct InfectedFiles{
  char *name;
  thr_t type;
  struct InfectedFiles *next;
} Ifiles;

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

int main(int argc,char *argv[]){
  time_t date;
  char *MD5 = "85578cd4404c6d586cd0ae1b36c98aca"; 
  char *SHA256 = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
  char *wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
  char *rootfolder;
  Fnames *allfiles=NULL,*temp;
  Ifiles *infected=NULL;
  int signature[]= {0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff, 0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10};
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
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Scanning Directory %s\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,rootfolder);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Found %d files\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Searching...\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    while(allfiles!=NULL){
      //Edw tha ginei i douleia
      printf("%s\n",allfiles->name);
      allfiles=allfiles->next;
    }
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Operation Finished\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Processed %d files. ",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    printf("\033[0;31m");
    printf("Found %d infected\n\n",infiles);
    printf("\033[0m");
    printf("%s:%s\n");
  }
  else if(!strcmp(argv[1],"inspect")){
    rootfolder = argv[2];
    listfiles(rootfolder,&nfiles,&allfiles);
    printf("\n[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Scanning Directory %s\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,rootfolder);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Found %d files\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Searching...\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Operation Finished\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Processed %d files.\n\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,nfiles);
  }
  else if(!strcmp(argv[1],"monitor")){
    rootfolder = argv[2];
    printf("\n[INFO] [9046] [%d-%s-%d %d:%d:%d] Application Started\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Monitoring Directory %s\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec,rootfolder);
    printf("[INFO] [9046] [%d-%s-%d %d:%d:%d] Waiting for events...\n",tm.tm_mday,Months[tm.tm_mon],tm.tm_year-100,tm.tm_hour,tm.tm_min,tm.tm_sec);
  }
  else if(!strcmp(argv[1],"slice")){
    printf("slice\n");
  }
  else if(!strcmp(argv[1],"unlock")){
    printf("unlock\n");
  }
  else{
    printf("Error mode not supported!\n");
  }
  return 0;
}
