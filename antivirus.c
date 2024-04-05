#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl"

int main(int argc,char **argv[]){
  if(!strcmp(argv[1],"scan")){

  }
  else if(!strcmp(argv[1],"inspect")){

  }
  else if(!strcmp(argv[1],"monitor")){

  }
  else if(!strcmp(argv[1],"slice")){

  }
  else if(!strcmp(argv[1],"unlock")){

  }
  else{
    printf("Error mode not supported!\n");
  }
  return 0;
}
