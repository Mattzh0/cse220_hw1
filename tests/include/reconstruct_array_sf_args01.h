const char *packets[] = {
"\x00\x1e\x0f\x32\x0e\xf4\x86\xcd\x00\x80\x02\x07\x10\xd6\x41\x0f\x00\x00\x00\x12\x00\x00\x00\x13\x00\x00\x00\x14\x00\x00\x00\x15",
"\x00\x1e\x0f\x32\x0e\xf4\x86\xcd\x00\x40\x02\x07\x10\xd6\x21\x0f\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00\x10\x00\x00\x00\x11",
"\x00\x1e\x0f\x32\x0e\xf4\x86\xcd\x00\x00\x02\x07\x10\xd6\x01\x0f\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00\x0d",
};
int reconstructed_array[] = {675349907, 997962218, 2021193812, 340631633, 909996593, 1092143830, 790789736, 1741697497, 82837431, 1075282486, 2109128536, 962800887, };
int expected_array[] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, };
unsigned int expected_num_elements = 12;