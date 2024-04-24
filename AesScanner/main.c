#include <Windows.h>
#include <stdio.h>
/*
��AES�㷨�е��ֽڴ���ԭ���֪S������S�о�����������
��S������S�ж�ռ��256�ֽ� ����S���е�ÿ���ֽ�������һ��S���н�����һ��
��S������S���ǻ���� ��n=S��[��S��[n]] n��[0,255]
�ɴ����Կ�����Ŀ����̵��ڴ�������ƥ���������Ե��ڴ�鶨λ��ʹ��AES���ܵ�S������S��
*/

//�ж�����S���Ƿ���Ի���
int isEquivalent(UINT8* sbox1, UINT8* sbox2) {
	for (int i = 0; i < 256; i++) {
		if (i != sbox2[sbox1[i]]) {
			return 0; // ���ȼ�
		}
	}
	return 1; // �ȼ�
}
BOOLEAN SBoxScan(PVOID Base,BYTE* Address, SIZE_T Size,OUT LPVOID* SBoxAddr,OUT LPVOID* RSBoxAddr) {
	UINT64 BitMap[4] = {0};
	LPVOID* Box=VirtualAlloc(0,sizeof(LPVOID)*256,MEM_COMMIT,PAGE_READWRITE);
	int BoxCount = 0;
	int n = 0;
	for (int i = 0; i < Size; i++) {
		for (int j = 0; j < 256; j++) {
			if (BitMap[Address[i+j] / 64] & (1ui64 << (Address[i+j] % 64))) {
				break;
			}
			BitMap[Address[i + j] / 64] |= (1ui64 << (Address[i + j] % 64));
			n++;
		}
		if (n==256) {
			Box[BoxCount++] = &Address[i];
			i += 255;
		}
		n = 0;
		BitMap[0] = BitMap[1] = BitMap[2] = BitMap[3] = 0;
	}

	//���ܻ��ҵ��������256�ֽڵ�
	if (BoxCount > 0) {
		for (int i = 0; i < BoxCount - 1; i++) {
			for (int j = i + 1; j < BoxCount; j++) {
				if (isEquivalent(Box[i], Box[j])) {
					printf("Find SBox:0x%llx RSBox:0x%llx\n", ((UINT64)Base) + (UINT_PTR)Box[i] - (UINT64)Address, ((UINT64)Base) + (UINT_PTR)Box[j] - (UINT64)Address);
					BYTE* SBox = Box[i];
					BYTE* RSBox = Box[j];
					for (int k = 0; k < 16; k++) {
						printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", SBox[k*16+0],SBox[k*16+1],SBox[k*16+2],SBox[k*16+3],SBox[k*16+4],SBox[k*16+5],SBox[k*16+6],SBox[k*16+7],SBox[k*16+8],SBox[k*16+9],SBox[k*16+10],SBox[k*16+11],SBox[k*16+12],SBox[k*16+13],SBox[k*16+14],SBox[k*16+15]);
					}
					printf("\n");
					for (int k = 0; k < 16; k++) {
						printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", RSBox[k * 16 + 0], RSBox[k * 16 + 1], RSBox[k * 16 + 2], RSBox[k * 16 + 3], RSBox[k * 16 + 4], RSBox[k * 16 + 5], RSBox[k * 16 + 6], RSBox[k * 16 + 7], RSBox[k * 16 + 8], RSBox[k * 16 + 9], RSBox[k * 16 + 10], RSBox[k * 16 + 11], RSBox[k * 16 + 12], RSBox[k * 16 + 13], RSBox[k * 16 + 14], RSBox[k * 16 + 15]);
					}
				
				}
			}
		}
	}
	VirtualFree(Box, 0, MEM_RELEASE);

}
VOID main() {
	DWORD ProcessId=0;
	HANDLE hProcess=INVALID_HANDLE_VALUE;
	while (hProcess==INVALID_HANDLE_VALUE) {
		printf("����һ������ID:");
		scanf("%d", &ProcessId);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	}
	
	MEMORY_BASIC_INFORMATION64 mbi;
	UINT64 pAddress = NULL;
	SIZE_T BufferSize = 1024 * 1024 * 256;
	LPVOID Buffer = VirtualAlloc(0, BufferSize, MEM_COMMIT, PAGE_READWRITE);
	LPVOID SBoxAddr;
	LPVOID RSBoxAddr;

	//�������S������S�д���ͬһ���ڴ����
	while (VirtualQueryEx(hProcess, pAddress,&mbi, sizeof(mbi))) {
		if (mbi.Protect != PAGE_NOACCESS&& mbi.Type!=MEM_FREE) {
			if (BufferSize < mbi.RegionSize) {
				VirtualFree(Buffer, 0, MEM_RELEASE);
				BufferSize = mbi.RegionSize;
				Buffer = VirtualAlloc(0, mbi.RegionSize, MEM_COMMIT, PAGE_READWRITE);
			}
			if (ReadProcessMemory(hProcess, mbi.BaseAddress, Buffer, mbi.RegionSize, 0)) {
				SBoxScan(mbi.BaseAddress, Buffer, mbi.RegionSize, &SBoxAddr, &RSBoxAddr);
			}
		}
		pAddress += mbi.RegionSize;
	}
	VirtualFree(Buffer, 0, MEM_RELEASE);
	getchar(); getchar();
}