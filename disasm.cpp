#include <iostream>
#include <fstream>

using std::cout;
using std::endl;
using std::ifstream;
using std::ios;
using std::streampos;
using std::string;
using std::shared_ptr;

namespace exe {
	const uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;

#pragma pack(push, 1)

	struct DOS_Header_t {
		struct {
			char a = 0,
				b = 0;
		} Magic;
		uint16_t LastPageSize = 0,
			Pages = 0,
			Relocations = 0,
			Headersize = 0,
			MinParagraphs = 0,
			MaxParagraphs = 0,
			InitialSS = 0,
			InitialSP = 0,
			Checksum = 0,
			InitialIP = 0,
			initialCS = 0,
			RelocationTable = 0,
			OverlayNumber = 0,
			ReservedA[4] = { 0 },
			OEM_ID = 0,
			OEM_Info = 0,
			ReservedB[10] = { 0 };
		uint32_t PE_HeaderAddr = 0;
	};

	struct PE_COFF_Header_t {
		uint16_t Machine = 0, NumberOfSections = 0;
		uint32_t TimeDateStamp = 0, PointerToSymbolTable = 0, NumberOfSymbols = 0;
		uint16_t SizeOfOptionalHeader = 0, Characteristics = 0;
	};

	struct PE_Optional_Header_t {
		unsigned char MajorLinkerVersion = 0, MinorLinkerVersion = 0;
		uint32_t SizeOfCode = 0,
			SizeOfInitializedData = 0,
			SizeOfUninitializedData = 0,
			AddressOfEntryPoint = 0,
			BaseOfCode = 0,
			BaseOfData = 0;
	};

#pragma pack(pop)

	class exefile {
		shared_ptr<char[]> ReadBytes(ifstream& file, const size_t readsize) {
			shared_ptr<char[]> data(new char[readsize] { 0 });
			file.read(data.get(), readsize);
			return shared_ptr<char[]>(data);
		}

		template <class T>
		void ReadData(ifstream& file, T& data, size_t readsize = sizeof(T)) {
			size_t actualsize = sizeof(T);
			if (readsize > actualsize) {
				throw "Read size is more than actual size!";
			}
			file.read((char*)&data, readsize);
		}

	public:
		string filename;
		DOS_Header_t DOS_Header;
		shared_ptr<char[]> DOS_Stub;
		struct {
			char a, b, c, d;
		} PE_Signature;
		PE_COFF_Header_t PE_COFF_Header;
		uint16_t PE_Optional_Magic = 0;
		PE_Optional_Header_t PE_Optional_Header;

		exefile(std::string filename) {
			this->filename = filename;
			ifstream exe(filename, ios::binary);

			ReadData(exe, DOS_Header);
			if (DOS_Header.Magic.a != 'M' || DOS_Header.Magic.b != 'Z') throw "EXE format not recognized!";

			size_t stublen = DOS_Header.PE_HeaderAddr - (size_t)exe.tellg();
			if (stublen > 0) DOS_Stub = ReadBytes(exe, stublen);
			if (DOS_Header.PE_HeaderAddr != exe.tellg()) throw "Error while reading PE Header!";

			ReadData(exe, PE_Signature);
			if (PE_Signature.a != 'P' || PE_Signature.b != 'E' || PE_Signature.c != 0 || PE_Signature.d != 0) throw "PE format not recognized!";

			ReadData(exe, PE_COFF_Header);
			if (!(PE_COFF_Header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) throw "Not an executable image!";

			ReadData(exe, PE_Optional_Magic);
			switch (PE_Optional_Magic) {
			case 0x10B:
				ReadData(exe, PE_Optional_Header);
				break;
			case 0x20B:
				ReadData(exe, PE_Optional_Header);
				break;
			default:
				throw "Unrecognized PE magic number!";
				break;
			}

			exe.close();
		}

		~exefile() {}
	};
}

int main() {
	exe::exefile Notepad("notepad.exe");
	cout << "Entry: " << std::hex << (void*)Notepad.PE_Optional_Header.AddressOfEntryPoint << endl;
	cout << "Base:  " << std::hex << (void*)Notepad.PE_Optional_Header.BaseOfCode << endl;
	return 0;
}
