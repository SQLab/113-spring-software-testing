#include <stdio.h>
#include <string.h>
#include "antiasan.h"

char gS[0x18];
char gBadBuf[0x87];

int main(void)
{
        strcpy(gBadBuf, "HAHAHAHAHAHAHAHAHAHAHAH");
        strcpy(gS, "HAHAHAHAHAHAHAHAHAHAHAH");
        printf("gBadBuf = %s\n", gBadBuf);
        printf("gS = %s\n", gS);
        antiasan((unsigned long)&gBadBuf);
        for (int i = 0; i < 0x10; i += 2) {
                gS[0x17 + i] = 'A';
                gS[0x17 + i + 1] = 'H';
        }
        printf("gS = %s\n", gS);
        return 0;
}
