#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  MAX_SECTIONS = 16,
  NUM_DATA_DIRECTORIES = 16,
  IMPORT_DIRECTORY = 1,
  MAX_IMPORT_DESCRIPTORS = 64,
  MAX_SECTION_NAME = 8,
  MAX_DLL_NAME = 128
};

enum {
  OK,
  ERR_CANT_OPEN,
  ERR_CANT_READ,
  ERR_BLACK_MAGIC,
  ERR_BAD_RVA,
  ERR_BAD_OFFSET,
  ERR_NO_MATCH,
  ERR_NO_CAVE,
  ERR_CANT_WRITE,
  ERR_TOO_LONG
};

#define CHECK(expr)                             \
  do {                                          \
    if ((err = (expr)) != OK)                   \
      return err;                               \
  } while(0)

#define CHECK_S(str, expr)                      \
  do {                                          \
    if ((err = (expr)) != OK) {                 \
      *errstr = (str);                          \
      return err;                               \
    }                                           \
  } while(0)

struct section_header
{
  char name[MAX_SECTION_NAME + 1];
  unsigned int virtual_size;
  unsigned int virtual_address;
  unsigned int raw_size;
  unsigned int raw_offset;
  unsigned int header_offset;
  unsigned int characteristics;
};

struct data_directory
{
  unsigned int virtual_address;
  unsigned int size;
  unsigned int directory_offset;
};

struct pe_info
{
  unsigned int num_sections;
  struct section_header section_headers[MAX_SECTIONS];
  struct data_directory data_directories[NUM_DATA_DIRECTORIES];
};

struct import_descriptor
{
  char name[MAX_DLL_NAME + 1];
  unsigned int name_offset;
  unsigned int descriptor_offset;
};

int read_u16(FILE *stream, unsigned int *data);

int read_u32(FILE *stream, unsigned int *data);

int write_u32(FILE *stream, unsigned int data);

int seek_pe_header(FILE *stream);

int read_pe_info(FILE *stream, struct pe_info *info);

int rva_to_section_index(const struct pe_info *info,
                         unsigned int rva,
                         int *index);

int rva_to_section_header(struct pe_info *info,
                          unsigned int rva,
                          struct section_header **header);

int import_directory_section_header(struct pe_info *info,
                                    struct section_header **header);

int rva_to_offset(const struct pe_info *info,
                  unsigned int rva,
                  unsigned int *offset);

int read_import_descriptors(FILE *stream,
                            const struct pe_info *info,
                            struct import_descriptor *descriptors,
                            int *ndescriptors);

int read_ntcs(FILE *stream, char *string, int n);

int write_ntcs(FILE *stream, const char *string);

int patch_in_place(FILE *stream,
                   const struct import_descriptor *descriptor,
                   const char *new_name);

int patch_in_cave(FILE *stream,
                  struct section_header *header,
                  struct import_descriptor *descriptor,
                  const char *new_name);

int patch_in_cave_alt(FILE *stream,
                      struct pe_info *info,
                      struct section_header *header,
                      struct import_descriptor *descriptor,
                      const char *new_name);

int rename_import_dll(const char *pe_file,
                      const char *old_name,
                      const char *new_name,
                      const char **errstr);

int main(int argc, char *argv[])
{
  int err;
  const char *errstr;

  printf("Rename Import DLL / arikba@ironsrc.com / compiled " __DATE__ "\n\n");

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pe-file> [<old-dll-name> <new-dll-name>]\n", argv[0]);
    return 1;
  }

  errstr = NULL;
  if (argc < 4) {
    err = rename_import_dll(argv[1], "", "", &errstr);
  } else {
    err = rename_import_dll(argv[1], argv[2], argv[3], &errstr);
  }

  if (err != OK) {
    fprintf(stderr, "Error: %s (code %d)\n\n", errstr ? errstr : "Unknown", err);
    return 1;
  }

  return 0;
}

int rename_import_dll(const char *pe_file,
                      const char *old_name,
                      const char *new_name,
                      const char **errstr)
{
  FILE *stream;
  struct pe_info info;
  struct import_descriptor descriptors[MAX_IMPORT_DESCRIPTORS];
  struct section_header *import_header;
  int ndescriptors;
  int descriptor_index;
  int i;
  int err;

  if (strlen(old_name) > MAX_DLL_NAME) {
    *errstr = "Old DLL name is too long";
    return ERR_TOO_LONG;
  }

  if (strlen(new_name) > MAX_DLL_NAME) {
    *errstr = "New DLL name is too long";
    return ERR_TOO_LONG;
  }

  if ((stream = fopen(pe_file, "r+b")) == NULL) {
    *errstr = "Can't open pe file";
    return ERR_CANT_OPEN;
  }

  CHECK_S("Can't read pe info", read_pe_info(stream, &info));

  printf("Sections:\n");
  for (i = 0; i < (int)info.num_sections; i++) {
    const struct section_header *header = &info.section_headers[i];
    printf("  %2d. %-8s  %10u  %10u  %10u  %10u  (%4u)\n",
           i, header->name,
           header->virtual_address, header->virtual_size,
           header->raw_offset, header->raw_size,
           header->raw_size > header->virtual_size
           ? header->raw_size - header->virtual_size
           : 0);
  }
  printf("\n");

  CHECK_S("Can't read import descriptors", read_import_descriptors(stream, &info, descriptors, &ndescriptors));

  printf("Import DLLs:\n");
  descriptor_index = -1;
  for (i = 0; i < ndescriptors; i++) {
    if (strcmp(descriptors[i].name, old_name) == 0) {
      descriptor_index = i;
      printf("  %s -> %s\n", descriptors[i].name, new_name);
    } else {
      printf("  %s\n", descriptors[i].name);
    }
  }
  printf("\n");

  if (*old_name) {
    if (descriptor_index == -1) {
      *errstr = "no matching import dll name";
      return ERR_NO_MATCH;
    }

    if (strlen(descriptors[descriptor_index].name) >= strlen(new_name)) {
      CHECK_S("Can't patch in-place", patch_in_place(stream, &descriptors[descriptor_index], new_name));
      printf("Patched in-place\n\n");
    } else {
      CHECK_S("Can't get section header for import directory", import_directory_section_header(&info, &import_header));
      err = patch_in_cave(stream, import_header, &descriptors[descriptor_index], new_name);
      if (err != OK) {
        printf("Couldn't patch in import directory's section, trying alternative sections\n");
        CHECK_S("Can't patch in cave", patch_in_cave_alt(stream, &info, import_header, &descriptors[descriptor_index], new_name));
      }
      printf("Patched in cave\n\n");
    }
  }

  fclose(stream);

  return OK;
}

int read_u16(FILE *stream, unsigned int *data)
{
  unsigned char buffer[2];

  if (fread(buffer, 1, 2, stream) != 2)
    return ERR_CANT_READ;

  *data = buffer[0] | (buffer[1] << 8);

  return OK;
}

int read_u32(FILE *stream, unsigned int *data)
{
  unsigned char buffer[4];

  if (fread(buffer, 1, 4, stream) != 4)
    return ERR_CANT_READ;

  *data = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);

  return OK;
}

int write_u32(FILE *stream, unsigned int data)
{
  unsigned char buffer[4];

  buffer[0] = data & 0xFF;
  buffer[1] = (data >> 8) & 0xFF;
  buffer[2] = (data >> 16) & 0xFF;
  buffer[3] = (data >> 24) & 0xFF;

  if (fwrite(buffer, 1, 4, stream) != 4)
    return ERR_CANT_WRITE;

  return OK;
}

#define U16(stream, outvar) CHECK(read_u16((stream), (outvar)))
#define U32(stream, outvar) CHECK(read_u32((stream), (outvar)))

int seek_pe_header(FILE *stream)
{
  unsigned int data;
  unsigned int lfanew;
  int err;

  fseek(stream, 0, SEEK_SET);
  U16(stream, &data);
  if (data != 0x5A4D)
    return ERR_BLACK_MAGIC;

  fseek(stream, 60, SEEK_SET);
  U32(stream, &lfanew);

  fseek(stream, lfanew, SEEK_SET);
  U32(stream, &data);
  if (data != 0x4550)
    return ERR_BLACK_MAGIC;

  fseek(stream, -4, SEEK_CUR);

  return OK;
}

int read_pe_info(FILE *stream, struct pe_info *info)
{
  int err;
  int i;
  unsigned int magic;
  int skip;

  CHECK(seek_pe_header(stream));

  fseek(stream, 6, SEEK_CUR);
  U16(stream, &info->num_sections);

  if (info->num_sections > MAX_SECTIONS) {
    fprintf(stderr, "Warning: more than max expected sections in pe file\n");
    info->num_sections = MAX_SECTIONS;
  }

  fseek(stream, 16, SEEK_CUR);
  U16(stream, &magic);
  switch (magic) {
  case 0x10B:
    skip = 94;
    break;
  case 0x20B:
    skip = 110;
    break;
  default:
    return ERR_BLACK_MAGIC;
  }

  fseek(stream, skip, SEEK_CUR);

  for (i = 0; i < NUM_DATA_DIRECTORIES; i++) {
    struct data_directory *directory = &info->data_directories[i];

    directory->directory_offset = ftell(stream);
    U32(stream, &directory->virtual_address);
    U32(stream, &directory->size);
  }

  for (i = 0; i < (int)info->num_sections; i++) {
    struct section_header *header = &info->section_headers[i];

    header->header_offset = ftell(stream);
    if (fread(&header->name, 1, MAX_SECTION_NAME, stream) != 8)
      return ERR_CANT_READ;
    header->name[MAX_SECTION_NAME] = '\0';
    U32(stream, &header->virtual_size);
    U32(stream, &header->virtual_address);
    U32(stream, &header->raw_size);
    U32(stream, &header->raw_offset);
    fseek(stream, 12, SEEK_CUR);
    U32(stream, &header->characteristics);
  }

  return OK;
}

int rva_to_section_index(const struct pe_info *info,
                         unsigned int rva,
                         int *index)
{
  int i;

  for (i = 0; i < (int)info->num_sections; i++) {
    const struct section_header *header = &info->section_headers[i];

    if (rva >= header->virtual_address &&
        rva < (header->virtual_address + header->virtual_size)) {
      *index = i;
      return OK;
    }
  }

  return ERR_BAD_RVA;
}

int rva_to_section_header(struct pe_info *info,
                          unsigned int rva,
                          struct section_header **header)
{
  int err;
  int section_index;

  CHECK(rva_to_section_index(info, rva, &section_index));
  *header = &info->section_headers[section_index];

  return OK;
}

int import_directory_section_header(struct pe_info *info,
                                    struct section_header **header)
{
  return rva_to_section_header(info, info->data_directories[IMPORT_DIRECTORY].virtual_address, header);
}

int rva_to_offset(const struct pe_info *info,
                  unsigned int rva,
                  unsigned int *offset)
{
  int i;
  int err;
  const struct section_header *header;

  CHECK(rva_to_section_index(info, rva, &i));

  header = &info->section_headers[i];
  *offset = rva - header->virtual_address;
  if (*offset > header->raw_size)
    return ERR_BAD_OFFSET;
  *offset += header->raw_offset;
  return OK;
}

int read_import_descriptors(FILE *stream,
                            const struct pe_info *info,
                            struct import_descriptor *descriptors,
                            int *ndescriptors)
{
  unsigned int offset;
  int err;

  CHECK(rva_to_offset(info, info->data_directories[IMPORT_DIRECTORY].virtual_address, &offset));
  fseek(stream, offset, SEEK_SET);

  *ndescriptors = 0;
  while (*ndescriptors < MAX_IMPORT_DESCRIPTORS) {
    unsigned int name_address;
    unsigned int save_offset;

    descriptors[*ndescriptors].descriptor_offset = ftell(stream);

    fseek(stream, 12, SEEK_CUR);
    U32(stream, &name_address);
    fseek(stream, 4, SEEK_CUR);

    if (name_address == 0)
      break;

    save_offset = ftell(stream);

    CHECK(rva_to_offset(info, name_address, &descriptors[*ndescriptors].name_offset));
    fseek(stream, descriptors[*ndescriptors].name_offset, SEEK_SET);

    CHECK(read_ntcs(stream, descriptors[*ndescriptors].name, MAX_DLL_NAME + 1));

    fseek(stream, save_offset, SEEK_SET);

    (*ndescriptors)++;
  }

  return OK;
}

int read_ntcs(FILE *stream,
              char *string,
              int n)
{
  int i;

  string[n - 1] = '\0';

  for (i = 0; i < n - 1; i++) {
    string[i] = fgetc(stream);
    if (string[i] == '\0')
      break;
  }

  return OK;
}

int write_ntcs(FILE *stream, const char *string)
{
  int n = strlen(string) + 1;

  if (fwrite(string, 1, n, stream) != n)
    return ERR_CANT_WRITE;

  return OK;
}

int patch_in_place(FILE *stream,
                   const struct import_descriptor *descriptor,
                   const char *new_name)
{
  int err;

  fseek(stream, descriptor->name_offset, SEEK_SET);
  CHECK(write_ntcs(stream, new_name));
  return OK;
}

int patch_in_cave(FILE *stream,
                  struct section_header *header,
                  struct import_descriptor *descriptor,
                  const char *new_name)
{
  int err;
  unsigned int cave_capacity;
  unsigned int cave_offset;
  unsigned int cave_rva;
  unsigned int name_size;

  if (header->raw_size <= header->virtual_size)
    return ERR_NO_CAVE;

  name_size = strlen(new_name) + 1;
  cave_capacity = header->raw_size - header->virtual_size;
  cave_offset = header->raw_offset + header->virtual_size;
  cave_rva = header->virtual_address + header->virtual_size;
  printf("Cave offset %u, capacity %u\n", cave_offset, cave_capacity);

  if (cave_capacity < name_size)
    return ERR_NO_CAVE;

  fseek(stream, cave_offset, SEEK_SET);
  CHECK(write_ntcs(stream, new_name));

  fseek(stream, descriptor->descriptor_offset + 12, SEEK_SET);
  CHECK(write_u32(stream, cave_rva));

  fseek(stream, header->header_offset + 8, SEEK_SET);
  CHECK(write_u32(stream, header->virtual_size + name_size));

  strcpy(descriptor->name, new_name);
  descriptor->name_offset = cave_offset;
  header->virtual_size += name_size;

  return OK;
}

int patch_in_cave_alt(FILE *stream,
                      struct pe_info *info,
                      struct section_header *import_header,
                      struct import_descriptor *descriptor,
                      const char *new_name)
{
  int err = ERR_NO_CAVE;
  int i;
  struct section_header *header;

  for (i = 0; i < (int)info->num_sections; i++) {
    header = &info->section_headers[i];
    if (header != import_header && header->characteristics == import_header->characteristics) {
      err = patch_in_cave(stream, header, descriptor, new_name);
      if (err == OK)
        break;
    }
  }

  return err;
}
