#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void gate(const char *input)
{
    if (strlen(input) != 8) {
        return;
    }

    if ((input[0] ^ input[1]) != 0x55) return;
    if ((input[2] + input[3]) != 200) return;
    if ((input[4] * 3) != input[5]) return;
    if ((input[6] - input[7]) != 1) return;

    if ((input[1] + input[2] - input[3]) != 50) return;
    if ((input[5] ^ input[6]) != 0x2A) return;

    puts("Correct! The flag is: CTF{symbolic_execution_for_the_win}");
    exit(0);
}

int main()
{
    char input[0x10] = {0};
    printf("Enter the secret key: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Strip newline
    gate(input);
    puts("Wrong key!");
    return 0;
}

