#include <cstdio>
#include <string>

using namespace std;

/*
MPEG-TS packet:
`        3                   2                   1                   0  `
`      1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0  `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `
`   0 |                             Header                            | `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `
`   4 |                  Adaptation field + Payload                   | `
`     |                                                               | `
` 184 |                                                               | `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `


MPEG-TS packet header:
`        3                   2                   1                   0  `
`      1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0  `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `
`   0 |       SB      |E|S|T|           PID           |TSC|AFC|   CC  | `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `

Sync byte                    (SB ) :  8 bits
Transport error indicator    (E  ) :  1 bit
Payload unit start indicator (S  ) :  1 bit
Transport priority           (T  ) :  1 bit
Packet Identifier            (PID) : 13 bits
Transport scrambling control (TSC) :  2 bits
Adaptation field control     (AFC) :  2 bits
Continuity counter           (CC ) :  4 bits
*/


//=============================================================================================================================================================================

class xTS
{
public:
  static constexpr uint32_t TS_PacketLength = 188;
  static constexpr uint32_t TS_HeaderLength = 4;

  static constexpr uint32_t PES_HeaderLength = 6;

  static constexpr uint32_t BaseClockFrequency_Hz         =    90000; //Hz
  static constexpr uint32_t ExtendedClockFrequency_Hz     = 27000000; //Hz
  static constexpr uint32_t BaseClockFrequency_kHz        =       90; //kHz
  static constexpr uint32_t ExtendedClockFrequency_kHz    =    27000; //kHz
  static constexpr uint32_t BaseToExtendedClockMultiplier =      300;
};

//=============================================================================================================================================================================

class xTS_PacketHeader
{
public:
  enum class ePID : uint16_t
  {
    PAT  = 0x0000,
    CAT  = 0x0001,
    TSDT = 0x0002,
    IPMT = 0x0003,
    NIT  = 0x0010, //DVB specific PID
    SDT  = 0x0011, //DVB specific PID
    NuLL = 0x1FFF,
  };

protected:
  uint8_t SB = 0;
  uint8_t E = 0;
  uint8_t S = 0;
  uint8_t T = 0;
  uint16_t PID = 0;
  uint8_t TSC = 0;
  uint8_t AFC = 0;
  uint8_t CC = 0;

public:
  void     Reset();
  int32_t  Parse(const uint8_t* Input);
  void     Print() const;

public:
  uint8_t getSB() {return this -> SB;}
  uint8_t getE() {return this -> E;}
  uint8_t getS() {return this -> S;}
  uint8_t getT() {return this -> T;}
  uint8_t getPID() {return this -> PID;}
  uint8_t getTSC() {return this -> TSC;}
  uint8_t getAFC() {return this -> AFC;}
  uint8_t getCC() {return this -> CC;}

public:
  //TODO
  bool     hasAdaptationField() const { return (this -> AFC == 1) ? false : true; }
  bool     hasPayload        () const { return (this -> AFC > 1) ? true : false; }
};

//*********************************************************

class xTS_AdaptationField {
public:
    uint8_t AFL;
    uint8_t DC;
    uint8_t RA;
    uint8_t SP;
    uint8_t PCR;
    uint8_t OPCR;
    uint8_t SP2;
    uint8_t TP;
    uint8_t EX;

public:
    void Reset();
    int32_t Parse(const uint8_t* Input, uint8_t Control);
    void Print() const;

public:
    uint32_t getBytes() const { return this->AFL; };
};

//=============================================================================================================================================================================

class xPES_PacketHeader {
  public:
    enum eStreamId: uint8_t {
        eStreamId_program_stream_map = 0xBC,
        eStreamId_padding_stream = 0xBE,
        eStreamId_private_stream_2 = 0xBF,
        eStreamId_ECM = 0xF0,
        eStreamId_EMM = 0xF1,
        eStreamId_program_stream_directory = 0xFF,
        eStreamId_DSMCC_stream = 0xF2,
        eStreamId_ITUT_H222_1_type_E = 0xF8,
    };

  protected:
    uint32_t m_PacketStartCodePrefix;
    uint8_t m_StreamId;
    uint16_t m_PacketLength;
    uint8_t PES_header_data_length;

  public:
    void Reset();
    int32_t Parse(const uint8_t * Input);
    void Print() const;

  public:
    uint32_t getPacketStartCodePrefix() const {
      return m_PacketStartCodePrefix;
    }
    uint8_t getStreamId() const {
      return m_StreamId;
    }
    uint16_t getPacketLength() const {
      return m_PacketLength;
    }
    uint8_t get_PES_header_data_length() {
      return PES_header_data_length;
    }
};

//***************************************************************

class xPES_Assembler {
  public:
    enum class eResult: int32_t {
        UnexpectedPID = 1,
        StreamPackedLost,
        AssemblingStarted,
        AssemblingContinue,
        AssemblingFinished,
    };

  protected:
    int32_t m_PID;

    uint8_t * m_Buffer;
    uint32_t m_BufferSize;
    uint32_t m_DataOffset;

    int8_t m_LastContinuityCounter;
    bool m_Started;
    xPES_PacketHeader m_PESH;

    FILE * pFile;

  public:
    xPES_Assembler();
    ~xPES_Assembler();
    void Init(int32_t PID);
    eResult AbsorbPacket(
      const uint8_t * TransportStreamPacket,
      const xTS_PacketHeader * PacketHeader,
      const xTS_AdaptationField * AdaptationField
    );
    void PrintPESH() const {
      m_PESH.Print();
    }
    uint8_t * getPacket() {
      return m_Buffer;
    }
    int32_t getNumPacketBytes() const {
      return m_DataOffset;
    }
    xPES_PacketHeader get_m_PESH() {
      return m_PESH;
    }
  protected:
    void xBufferReset();
    void xBufferAppend(const uint8_t * Data, int32_t Size);
};

//=============================================================================================================================================================================
// xTS_PacketHeader
//=============================================================================================================================================================================

void xTS_PacketHeader::Reset(){
    this -> SB = 0;
    this -> E = 0;
    this -> S = 0;
    this -> T = 0;
    this -> PID = 0;
    this -> TSC = 0;
    this -> AFC = 0;
    this -> CC = 0;
}

int32_t xTS_PacketHeader::Parse(const uint8_t *Input){
    uint32_t byte = 0;
    for(int i=0; i<4; i++) {
        byte <<= 8;
        byte = byte | *(Input+i);
    }

    this->SB  = ((byte & 0xff000000) >> 24);
    this->E   = ((byte & 0x800000)   >> 23);
    this->S   = ((byte & 0x400000)   >> 22);
    this->T   = ((byte & 0x200000)   >> 21);
    this->PID = ((byte & 0x1fff00)   >>  8);
    this->TSC = ((byte & 0xc0)       >>  6);
    this->AFC = ((byte & 0x30)       >>  4);
    this->CC  = ((byte & 0xf)        >>  0);
}

void xTS_PacketHeader::Print(){
    printf("TS: ");
    printf("SB=%d ",this -> SB);
    printf("E=%d ",this -> E);
    printf("S=%d ",this -> S);
    printf("T=%d ",this -> T);
    printf("PID=%d ",this -> PID);
    printf("TSC=%d ",this -> TSC);
    printf("AFC=%d ",this -> AFC);
    printf("CC=%d ",this -> CC);
}

//******************************************************

void xTS_AdaptationField::Reset() {
    this->AFL  = 0;
    this->DC   = 0;
    this->RA   = 0;
    this->SP   = 0;
    this->PR  = 0;
    this->OR = 0;
    this->SP2  = 0;
    this->TP   = 0;
    this->EX   = 0;

    this->program_clock_reference_base = 0;
    this->program_clock_reference_extension = 0;

    this->original_program_clock_reference_base = 0;
    this->original_program_clock_reference_extension = 0;

    this->splice_countdown = 0;
    this->transport_private_data_length = 0;
    this->stuffing_byte_length = 0;
}

int32_t xTS_AdaptationField::Parse(const uint8_t* Input, uint8_t Control) {
    int AF_offset = 4;
    this->AFL = *(Input+AF_offset);
    AF_offset = 5;
    int i = 0;
    uint8_t flags = *(Input+AF_offset+(i++));
    this->DC = ((flags & 0x80) >> 7);
    this->RA = ((flags & 0x40) >> 6);
    this->SP = ((flags & 0x20) >> 5);
    this->PR = ((flags & 0x10) >> 4);
    this->OR = ((flags & 0x8)  >> 3);
    this->SP2 = ((flags & 0x4)  >> 2);
    this->TP = ((flags & 0x2)  >> 1);
    this->EX = ((flags & 0x1)  >> 0);
}

void xTS_AdaptationField::Print() const {
    printf("AF: ");
    printf("L=%3d ", this->getBytes());
    printf("DC=%d ", this->DC);
    printf("RA=%d ", this->RA);
    printf("SP=%d ", this->SP);
    printf("PR=%d ", this->PR);
    printf("OR=%d ", this->OR);
    printf("SP=%d ", this->SP2);
    printf("TP=%d ", this->TP);
    printf("EX=%d ", this->EX);
}

//=============================================================================================================================================================================

void xPES_PacketHeader::Reset() {
  this->m_PacketStartCodePrefix = 0;
  this->m_StreamId = 0;
  this->m_PacketLength = 0;
}

int32_t xPES_PacketHeader::Parse(const uint8_t* Input) {
  for(int i=0; i<3; i++) {
    this->m_PacketStartCodePrefix <<= 8;
    this->m_PacketStartCodePrefix = this->m_PacketStartCodePrefix | *(Input+i);
  }

  this->m_StreamId = *(Input+3);

  for(int i=0; i<2; i++) {
    this->m_PacketLength <<= 8;
    this->m_PacketLength = this->m_PacketLength | *(Input+4+i);
  }

  if(this->m_StreamId != eStreamId_program_stream_map &&
     this->m_StreamId != eStreamId_padding_stream &&
     this->m_StreamId != eStreamId_private_stream_2 &&
     this->m_StreamId != eStreamId_ECM &&
     this->m_StreamId != eStreamId_EMM &&
     this->m_StreamId != eStreamId_program_stream_directory &&
     this->m_StreamId != eStreamId_DSMCC_stream &&
     this->m_StreamId != eStreamId_ITUT_H222_1_type_E) {

        this->PES_header_data_length = *(Input+8)+6+2+1;
        uint32_t PTS = 0;
        uint32_t DTS = 0;
    }
}

void xPES_PacketHeader::Print() const {
  printf("PES: ");
  printf("PSCP=%d ", this->m_PacketStartCodePrefix);
  printf("SID=%d ", this->m_StreamId);
  printf("L=%d ", this->m_PacketLength);
}

//****************************************************************************************************

xPES_Assembler::xPES_Assembler() {
  this->m_PID = 0;

  this->m_Buffer = NULL;
  this->m_BufferSize = 0;
  this->m_DataOffset = 0;

  this->m_LastContinuityCounter = 0;
  this->m_Started = 0;
  this->m_PESH.Reset();

  this->pFile = NULL;
}

xPES_Assembler::~xPES_Assembler() {
  fclose(this->pFile);
}

void xPES_Assembler::Init(int32_t PID) {
  this->m_PID = PID;
  this->m_LastContinuityCounter = 15;
  this->pFile = fopen("PID136.mp2", "wb");
}

xPES_Assembler::eResult xPES_Assembler::AbsorbPacket (
  const uint8_t * TransportStreamPacket,
  const xTS_PacketHeader * PacketHeader,
  const xTS_AdaptationField * AdaptationField
) {
  this->m_Started = (*PacketHeader).getS();
  uint8_t length = 188;
  uint8_t offset = 4; //TS_HeaderLength
  if((*PacketHeader).hasAdaptationField()) {
    offset += 1; //xTS_AdaptationField adaptation_field_length
    offset += (*AdaptationField).getNumBytes();
  }

  length -= offset; //188B - TS_Packet bytes

  int cc = (*PacketHeader).getCC();
  if(cc != ((this->m_LastContinuityCounter+1)%16) ) {
    printf("ContinuityCounter not valid");
  }
  this->m_LastContinuityCounter = cc;

  xPES_Assembler::eResult res;

  if(this->m_Started) {
    this->m_PESH.Reset();
    this->m_PESH.Parse(TransportStreamPacket+offset);
    res = xPES_Assembler::eResult::AssemblingStarted;
  }
  else if(this->m_DataOffset + length == this->m_BufferSize) {
    res = xPES_Assembler::eResult::AssemblingFinished;
  }
  else {
    res = xPES_Assembler::eResult::AssemblingContinue;
  }

  this->xBufferAppend(TransportStreamPacket+offset, length);
  return res;
}

void xPES_Assembler::xBufferReset() {
  this->m_BufferSize = 0;
  this->m_DataOffset = 0;
}

void xPES_Assembler::xBufferAppend(const uint8_t * Data, int32_t Size) {
  if(this->m_Started == true) {
    this->xBufferReset();
    this->m_BufferSize = this->m_PESH.getPacketLength()-(this->get_m_PESH().get_PES_header_data_length()-6);

    if(!this->m_Buffer) {
      this->m_Buffer = (uint8_t*) malloc (sizeof(uint8_t)* this->m_BufferSize);
    }
    else {
      uint8_t* ptr = (uint8_t*) realloc (this->m_Buffer, sizeof(uint8_t)* this->m_BufferSize);
      if (ptr != NULL) {
        this->m_Buffer = ptr;
      }
      else {
        free(this->m_Buffer);
        puts("Reallocating memory");
        exit(1);
      }
    }
  }

  int i = (this->m_Started) ? this->get_m_PESH().get_PES_header_data_length() : 0;
  for(i; i<Size; i++) {
    *(this->m_Buffer+this->m_DataOffset) = *(Data+i);
    this->m_DataOffset++;
  }

  if(this->m_DataOffset == this->m_BufferSize) {
    fwrite(this->m_Buffer, 1, this->m_BufferSize, this->pFile);
  }
}


int main( int argc, char *argv[ ], char *envp[ ])
{
  FILE * stream = fopen("example_new.ts", "rb");
  int TS_Size = 188;
  size_t open_Stream;

  xTS_PacketHeader    TS_PacketHeader;
  xTS_AdaptationField TS_AdaptationField;
  xPES_Assembler PES_Assembler;
  PES_Assembler.Init(136);

  uint8_t * TS_PacketBuffer;
  TS_PacketBuffer = (uint8_t*) malloc (sizeof(uint8_t)*TS_Size);

  int32_t TS_PacketId = 0;
  while(!feof(stream))
  {
    open_Stream = fread(TS_PacketBuffer,1,TS_Size,stream);

    TS_PacketHeader.Reset();
    TS_PacketHeader.Parse(TS_PacketBuffer);

    printf("%010d ", TS_PacketId);
    TS_PacketHeader.Print();

    if(TS_PacketHeader.hasAdaptationField()) {
      TS_AdaptationField.Reset();
      TS_AdaptationField.Parse(TS_PacketBuffer, TS_PacketHeader.getAFC());
      printf("\n           ");
      TS_AdaptationField.Print();
    }

    if (TS_PacketHeader.getPID() == 136) {
        xPES_Assembler::eResult Result = PES_Assembler.AbsorbPacket(TS_PacketBuffer, &TS_PacketHeader, &TS_AdaptationField);
        switch (Result) {

            case xPES_Assembler::eResult::StreamPackedLost:
                printf("PackedLost");
                break;

            case xPES_Assembler::eResult::AssemblingStarted:
                printf("\n");
                printf("Started");
                printf("\n");
                PES_Assembler.PrintPESH();
                break;

            case xPES_Assembler::eResult::AssemblingContinue:
                printf("Continue");
                break;

            case xPES_Assembler::eResult::AssemblingFinished:
                printf("\n");
                printf("Finished");
                printf("\n");
                printf("PES: Len=%d HeaderLen=%d DataLen=%d",
                PES_Assembler.get_m_PESH().getPacketLength()+6,
                PES_Assembler.get_m_PESH().get_PES_header_data_length(),
                PES_Assembler.getNumPacketBytes());
                break;

            default:
                break;
      }
    }

    printf("\n");

    TS_PacketId++;
  }
  fclose (stream);
  free (TS_PacketBuffer);
}
