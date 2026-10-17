/* Harmless demo program used only as a Malvexis test fixture. */
#include <windows.h>
#include <stdio.h>
int main(void) {
    char host[256]; DWORD n = sizeof(host);
    GetComputerNameA(host, &n);
    char s[] = {'m','a','l','v','e','x','i','s','_','s','t','a','c','k','_','d','e','m','o',0};
    HANDLE h = CreateFileA("malvexis_demo.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD w; WriteFile(h, s, (DWORD)(sizeof(s) - 1), &w, NULL); CloseHandle(h);
    printf("host=%s docs: https://example.com/docs\n", host);
    Sleep(10);
    return 0;
}
