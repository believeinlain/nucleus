#ifndef NUCLEUS_LOADER_H
#define NUCLEUS_LOADER_H

#include <stdint.h>
#include <string>
#include <vector>

/* RN replace old macros */
#define bfd_get_section_flags(bfd, ptr) ((void) bfd, (ptr)->flags)
#define bfd_get_section_userdata(bfd, ptr) ((void) bfd, (ptr)->userdata)
#define bfd_get_section_vma(bfd, ptr) ((void) bfd, (ptr)->vma)
#define bfd_get_section_size(ptr) ((ptr)->size)

class Binary;
class Section;
class Symbol;

class Symbol {
public:
  enum SymbolType {
    SYM_TYPE_UKN  = 0x000,
    SYM_TYPE_FUNC = 0x001
  };

  Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}

  unsigned    type;
  std::string name;
  uint64_t    addr;
};

class Section {
public:
  enum SectionType {
    SEC_TYPE_NONE = 0,
    SEC_TYPE_CODE = 1,
    SEC_TYPE_DATA = 2
  };

  Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}

  bool contains        (uint64_t addr) { return (addr >= vma) && (addr-vma < size); }
  bool is_import_table ()              { return name == ".plt"; }

  Binary       *binary;
  std::string   name;
  SectionType   type;
  uint64_t      vma;
  uint64_t      size;
  uint8_t       *bytes;
};

class Binary {
public:
  enum BinaryType {
    BIN_TYPE_AUTO = 0,
    BIN_TYPE_RAW  = 1,
    BIN_TYPE_ELF  = 2,
    BIN_TYPE_PE   = 3,
    BIN_TYPE_MACH = 4
  };
  enum BinaryArch {
    ARCH_NONE    = 0,
    ARCH_AARCH64 = 1,
    ARCH_ARM     = 2,
    ARCH_MIPS    = 3,
    ARCH_PPC     = 4,
    ARCH_X86     = 5,
    ARCH_RISCV   = 6
  };

  Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}

  Section *get_text_section() { for(auto &s : sections) if(s.name == ".text") return &s; return NULL; }

  std::string          filename;
  BinaryType           type;
  std::string          type_str;
  BinaryArch           arch;
  std::string          arch_str;
  unsigned             bits;
  uint64_t             entry;
  std::vector<Section> sections;
  std::vector<Symbol>  symbols;
};

int  load_binary   (std::string &fname, Binary *bin, Binary::BinaryType type);
void unload_binary (Binary *bin);

#endif /* NUCLEUS_LOADER_H */

