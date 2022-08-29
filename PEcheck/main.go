package main

import (
	"fmt"
	"os"
)

type _IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

func findSignature(file string) int64 {
	// Open the file
	f, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	defer f.Close()

	// read each 4 bytes
	var buf [4]byte
	var pos int64 = 0
	for {
		pos += 4
		// read 4 bytes
		_, err := f.Read(buf[:])
		if err != nil {
			break
		}
		// check if it is the PE signature
		if buf[0] == 'P' && buf[1] == 'E' && buf[2] == 0 && buf[3] == 0 {

			fmt.Printf("Found PE signature at offset: 0x%x\n", pos)
			return pos
		}
	}
	return -1
}

// read byte at offset
func getMachine(file string, offset int64) []byte {
	// Open the file
	f, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer f.Close()

	// read byte at offset
	var buf [2]byte
	_, err = f.ReadAt(buf[:], offset)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return buf[:]
}

func ParseOptionalHeader(file string, offset int64, mode int64) uint16 {
	// Open the file
	f, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		return 0
	}
	defer f.Close()

	if mode == 32 {
		var buf [0xE0]byte
		_, err = f.ReadAt(buf[:], offset)
		if err != nil {
			fmt.Println(err)
			return 0
		}
		// Parse IMAGE_OPTIONAL_HEADER32
		optionalHeader := _IMAGE_OPTIONAL_HEADER32{
			Magic:                       uint16(buf[0]) | uint16(buf[1])<<8,
			MajorLinkerVersion:          uint8(buf[2]),
			MinorLinkerVersion:          uint8(buf[3]),
			SizeOfCode:                  uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24,
			SizeOfInitializedData:       uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24,
			SizeOfUninitializedData:     uint32(buf[12]) | uint32(buf[13])<<8 | uint32(buf[14])<<16 | uint32(buf[15])<<24,
			AddressOfEntryPoint:         uint32(buf[16]) | uint32(buf[17])<<8 | uint32(buf[18])<<16 | uint32(buf[19])<<24,
			BaseOfCode:                  uint32(buf[20]) | uint32(buf[21])<<8 | uint32(buf[22])<<16 | uint32(buf[23])<<24,
			BaseOfData:                  uint32(buf[24]) | uint32(buf[25])<<8 | uint32(buf[26])<<16 | uint32(buf[27])<<24,
			ImageBase:                   uint32(buf[28]) | uint32(buf[29])<<8 | uint32(buf[30])<<16 | uint32(buf[31])<<24,
			SectionAlignment:            uint32(buf[32]) | uint32(buf[33])<<8 | uint32(buf[34])<<16 | uint32(buf[35])<<24,
			FileAlignment:               uint32(buf[36]) | uint32(buf[37])<<8 | uint32(buf[38])<<16 | uint32(buf[39])<<24,
			MajorOperatingSystemVersion: uint16(buf[40]) | uint16(buf[41])<<8,
			MinorOperatingSystemVersion: uint16(buf[42]) | uint16(buf[43])<<8,
			MajorImageVersion:           uint16(buf[44]) | uint16(buf[45])<<8,
			MinorImageVersion:           uint16(buf[46]) | uint16(buf[47])<<8,
			MajorSubsystemVersion:       uint16(buf[48]) | uint16(buf[49])<<8,
			MinorSubsystemVersion:       uint16(buf[50]) | uint16(buf[51])<<8,
			Win32VersionValue:           uint32(buf[52]) | uint32(buf[53])<<8 | uint32(buf[54])<<16 | uint32(buf[55])<<24,
			SizeOfImage:                 uint32(buf[56]) | uint32(buf[57])<<8 | uint32(buf[58])<<16 | uint32(buf[59])<<24,
			SizeOfHeaders:               uint32(buf[60]) | uint32(buf[61])<<8 | uint32(buf[62])<<16 | uint32(buf[63])<<24,
			CheckSum:                    uint32(buf[64]) | uint32(buf[65])<<8 | uint32(buf[66])<<16 | uint32(buf[67])<<24,
			Subsystem:                   uint16(buf[68]) | uint16(buf[69])<<8,
			DllCharacteristics:          uint16(buf[70]) | uint16(buf[71])<<8,
			SizeOfStackReserve:          uint32(buf[72]) | uint32(buf[73])<<8 | uint32(buf[74])<<16 | uint32(buf[75])<<24,
			SizeOfStackCommit:           uint32(buf[76]) | uint32(buf[77])<<8 | uint32(buf[78])<<16 | uint32(buf[79])<<24,
			SizeOfHeapReserve:           uint32(buf[80]) | uint32(buf[81])<<8 | uint32(buf[82])<<16 | uint32(buf[83])<<24,
			SizeOfHeapCommit:            uint32(buf[84]) | uint32(buf[85])<<8 | uint32(buf[86])<<16 | uint32(buf[87])<<24,
			LoaderFlags:                 uint32(buf[88]) | uint32(buf[89])<<8 | uint32(buf[90])<<16 | uint32(buf[91])<<24,
			NumberOfRvaAndSizes:         uint32(buf[92]) | uint32(buf[93])<<8 | uint32(buf[94])<<16 | uint32(buf[95])<<24,
		}
		return optionalHeader.DllCharacteristics
	} else if mode == 64 {
		var buf [0xF0]byte
		_, err = f.ReadAt(buf[:], offset)
		if err != nil {
			fmt.Println(err)
			return 0
		}
		// Parse IMAGE_OPTIONAL_HEADER64
		optionalHeader := _IMAGE_OPTIONAL_HEADER64{
			Magic:                       uint16(buf[0]) | uint16(buf[1])<<8,
			MajorLinkerVersion:          uint8(buf[2]),
			MinorLinkerVersion:          uint8(buf[3]),
			SizeOfCode:                  uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24,
			SizeOfInitializedData:       uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24,
			SizeOfUninitializedData:     uint32(buf[12]) | uint32(buf[13])<<8 | uint32(buf[14])<<16 | uint32(buf[15])<<24,
			AddressOfEntryPoint:         uint32(buf[16]) | uint32(buf[17])<<8 | uint32(buf[18])<<16 | uint32(buf[19])<<24,
			BaseOfCode:                  uint32(buf[20]) | uint32(buf[21])<<8 | uint32(buf[22])<<16 | uint32(buf[23])<<24,
			ImageBase:                   uint64(buf[24]) | uint64(buf[25])<<8 | uint64(buf[26])<<16 | uint64(buf[27])<<24 | uint64(buf[28])<<32 | uint64(buf[29])<<40 | uint64(buf[30])<<48 | uint64(buf[31])<<56,
			SectionAlignment:            uint32(buf[32]) | uint32(buf[33])<<8 | uint32(buf[34])<<16 | uint32(buf[35])<<24,
			FileAlignment:               uint32(buf[36]) | uint32(buf[37])<<8 | uint32(buf[38])<<16 | uint32(buf[39])<<24,
			MajorOperatingSystemVersion: uint16(buf[40]) | uint16(buf[41])<<8,
			MinorOperatingSystemVersion: uint16(buf[42]) | uint16(buf[43])<<8,
			MajorImageVersion:           uint16(buf[44]) | uint16(buf[45])<<8,
			MinorImageVersion:           uint16(buf[46]) | uint16(buf[47])<<8,
			MajorSubsystemVersion:       uint16(buf[48]) | uint16(buf[49])<<8,
			MinorSubsystemVersion:       uint16(buf[50]) | uint16(buf[51])<<8,
			Win32VersionValue:           uint32(buf[52]) | uint32(buf[53])<<8 | uint32(buf[54])<<16 | uint32(buf[55])<<24,
			SizeOfImage:                 uint32(buf[56]) | uint32(buf[57])<<8 | uint32(buf[58])<<16 | uint32(buf[59])<<24,
			SizeOfHeaders:               uint32(buf[60]) | uint32(buf[61])<<8 | uint32(buf[62])<<16 | uint32(buf[63])<<24,
			CheckSum:                    uint32(buf[64]) | uint32(buf[65])<<8 | uint32(buf[66])<<16 | uint32(buf[67])<<24,
			Subsystem:                   uint16(buf[68]) | uint16(buf[69])<<8,
			DllCharacteristics:          uint16(buf[70]) | uint16(buf[71])<<8,
			SizeOfStackReserve:          uint64(buf[72]) | uint64(buf[73])<<8 | uint64(buf[74])<<16 | uint64(buf[75])<<24 | uint64(buf[76])<<32 | uint64(buf[77])<<40 | uint64(buf[78])<<48 | uint64(buf[79])<<56,
			SizeOfStackCommit:           uint64(buf[80]) | uint64(buf[81])<<8 | uint64(buf[82])<<16 | uint64(buf[83])<<24 | uint64(buf[84])<<32 | uint64(buf[85])<<40 | uint64(buf[86])<<48 | uint64(buf[87])<<56,
			SizeOfHeapReserve:           uint64(buf[88]) | uint64(buf[89])<<8 | uint64(buf[90])<<16 | uint64(buf[91])<<24 | uint64(buf[92])<<32 | uint64(buf[93])<<40 | uint64(buf[94])<<48 | uint64(buf[95])<<56,
			SizeOfHeapCommit:            uint64(buf[96]) | uint64(buf[97])<<8 | uint64(buf[98])<<16 | uint64(buf[99])<<24 | uint64(buf[100])<<32 | uint64(buf[101])<<40 | uint64(buf[102])<<48 | uint64(buf[103])<<56,
			LoaderFlags:                 uint32(buf[104]) | uint32(buf[105])<<8 | uint32(buf[106])<<16 | uint32(buf[107])<<24,
			NumberOfRvaAndSizes:         uint32(buf[108]) | uint32(buf[109])<<8 | uint32(buf[110])<<16 | uint32(buf[111])<<24,
		}
		return optionalHeader.DllCharacteristics
	}
	return 0
}

func main() {
	var mode int64
	var IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE int64 = 0
	var IMAGE_DLLCHARACTERISTICS_GUARD_CF int64 = 0
	var IMAGE_DLLCHARACTERISTICS_WDM_DRIVER int64 = 0
	var IMAGE_DLLCHARACTERISTICS_APPCONTAINER int64 = 0
	var IMAGE_DLLCHARACTERISTICS_NO_BIND int64 = 0
	var IMAGE_DLLCHARACTERISTICS_NO_SEH int64 = 0
	var IMAGE_DLLCHARACTERISTICS_NO_ISOLATION int64 = 0
	var MAGE_DLLCHARACTERISTICS_NX_COMPAT int64 = 0
	var IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY int64 = 0
	var IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE int64 = 0
	var IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA int64 = 0

	// get the file name from the command line
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], "filename")
		os.Exit(1)
	}
	filepath := os.Args[1]
	Pos := findSignature(filepath)

	if Pos == -1 {
		fmt.Println("Cannot find PE signature")
		return
	}
	// read byte at offset
	buf := getMachine(filepath, Pos)
	if buf == nil {
		fmt.Println("Cannot read byte at offset")
		return
	}
	if buf[0] == 0x4c && buf[1] == 0x01 {
		fmt.Println("Machine 32 bit")
		mode = 32
	}
	if buf[0] == 0x64 && buf[1] == 0x86 {
		fmt.Println("Machine 64 bit")
		mode = 64
	}

	// IMAGE_OPTIONAL_HEADER
	Pos += 0x14
	DllCharacteristics := ParseOptionalHeader(filepath, Pos, mode)

	if DllCharacteristics&0xF000 == 0x8000 {
		IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0
	}
	if DllCharacteristics&0xF000 == 0x4000 {
		IMAGE_DLLCHARACTERISTICS_GUARD_CF = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0
	}
	if DllCharacteristics&0xF000 == 0x2000 {
		IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0
	}
	if DllCharacteristics&0xF000 == 0x1000 {
		IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0
	}
	if DllCharacteristics&0x0F00 == 0x0800 {
		IMAGE_DLLCHARACTERISTICS_NO_BIND = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_NO_BIND = 0
	}
	if DllCharacteristics&0x0F00 == 0x0400 {
		IMAGE_DLLCHARACTERISTICS_NO_SEH = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_NO_SEH = 0
	}
	if DllCharacteristics&0x0F00 == 0x0200 {
		IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0
	}
	if DllCharacteristics&0x0F00 == 0x0100 {
		MAGE_DLLCHARACTERISTICS_NX_COMPAT = 1
	} else {
		MAGE_DLLCHARACTERISTICS_NX_COMPAT = 0
	}
	if DllCharacteristics&0x00F0 == 0x0080 {
		IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0
	}
	if DllCharacteristics&0x00F0 == 0x0040 {
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0
	}
	if DllCharacteristics&0x00F0 == 0x0020 {
		IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 1
	} else {
		IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0
	}

	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: %d\n", IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_GUARD_CF (Control Flow Guard): %d\n", IMAGE_DLLCHARACTERISTICS_GUARD_CF)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: %d\n", IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_APPCONTAINER: %d\n", IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_NO_BIND: %d\n", IMAGE_DLLCHARACTERISTICS_NO_BIND)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_NO_SEH: %d\n", IMAGE_DLLCHARACTERISTICS_NO_SEH)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: %d\n", IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
	fmt.Printf("[+] MAGE_DLLCHARACTERISTICS_NX_COMPAT: %d\n", MAGE_DLLCHARACTERISTICS_NX_COMPAT)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: %d\n", IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR): %d\n", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	fmt.Printf("[+] IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: %d\n", IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)

}
