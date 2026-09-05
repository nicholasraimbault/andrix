#include <unistd.h>

static const char kMsg[] = "andrix\n";

int main(void) {
    write(STDOUT_FILENO, kMsg, sizeof(kMsg) - 1);
    _exit(0);
}
