#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    FILE* f1 = fopen("zakukozh.bin","rb");
    unsigned char c[10];
    fread(c, 8,1,f1);
    //printf("%x",c[2]);
    int i1 = c[0],i2 = c[1],i3 = c[2];
    int a1,a2,a3,i,j;
    printf("%d %d %d \n",i1,i2,i3);
    int ri,rj ;
    for(i=0;i<256;i++)
    for (j=0;j<256;j++){
    	a1 = i*i1+j;a2 = i*i2+j;a3 = i*i3+j;
    	if (a1%256==0x89&&a2%256==0x50) {
		printf("%d %d \n",i,j);
		ri=i;rj=j;
		} 
    	//PNG no
	}
	fclose(f1);
	FILE* f2 = fopen("zakukozh.bin","rb");
	FILE* fw = fopen("zakukozh.bin1","wb");
	while(!feof(f2)){
		fread(c, 1,1,f2);
		//printf("%x ",c[0]);
		c[0] = (c[0]*ri+rj)%256;
		//printf("%x ",c[0]);
		fwrite(c,1,1,fw);
	}
	fclose(f2);
    fclose(fw);
    return 0;
}
