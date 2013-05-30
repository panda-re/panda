/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#include "android/utils/path.h"
#include "android/utils/misc.h"
#include "android/utils/debug.h"
#include "android/utils/system.h"
#include "android/charmap.h"
#include <stdio.h>
#include <errno.h>

/* Parses .kcm file producing key characters map.
 * .kcm file parsed by this module is expected to contain 4 types of
 * lines:
 * 1. An empty line (containing no characters, or only space or tab
 *    characters).
 * 2. A comment line (begins with '#')
 * 3. A type section line (begins with '[')
 * 4. Character map line, formatted as such:
 * Key code value, followed by one or more space or tab characters.
 * Display value, followed by one or more space or tab characters.
 * Number value, followed by one or more space or tab characters.
 * Base value, followed by one or more space or tab characters.
 * Caps value, followed by one or more space or tab characters.
 * Fn value, followed by one or more space or tab characters.
 * Caps_fn value, followed by one or more space or tab characters.
 * All values, except for the key code value must be either in character
 * form ('X', where X is the value), or in hexadecimal form (0xXXXX, where
 * XXXX is hexadecimal representation of the value). Note that if value is
 * in hexadecimal form, it must not exceed value that can be contained in
 * variable of 'unsigned short' type.
 * Bellow are a couple of examples of valid .kcm file lines:
 * # keycode       display number  base    caps    fn      caps_fn
 * A               'A'     '2'     'a'     'A'     '#'     0x00
 * PERIOD          '.'     '.'     '.'     ':'     ':'     0x2026
 * SPACE           0x20    0x20    0x20    0x20    0xEF01  0xEF01
*/

/* Maximum length of a line expected in .kcm file. */
#define KCM_MAX_LINE_LEN    1024

/* Maximum length of a token in a key map line. */
#define KCM_MAX_TOKEN_LEN   512

/* Maps symbol name from .kcm file to a keycode value. */
typedef struct AKeycodeMapEntry {
    /* Symbol name from .kcm file. */
    const char* key_name;

    /* Key code value for the symbol. */
    int         key_code;
} AKeycodeMapEntry;

/* Result of parsing a line in a .kcm file. */
typedef enum {
    /* Line format was bad. */
    BAD_FORMAT,

    /* Line had been skipped (an empty line, or a comment, etc.). */
    SKIP_LINE,

    /* Line represents an entry in the key map. */
    KEY_ENTRY,
} ParseStatus;

static const AKeycodeMapEntry keycode_map[] = {
    /*  Symbol           Key code */

      { "A",             kKeyCodeA },
      { "B",             kKeyCodeB },
      { "C",             kKeyCodeC },
      { "D",             kKeyCodeD },
      { "E",             kKeyCodeE },
      { "F",             kKeyCodeF },
      { "G",             kKeyCodeG },
      { "H",             kKeyCodeH },
      { "I",             kKeyCodeI },
      { "J",             kKeyCodeJ },
      { "K",             kKeyCodeK },
      { "L",             kKeyCodeL },
      { "M",             kKeyCodeM },
      { "N",             kKeyCodeN },
      { "O",             kKeyCodeO },
      { "P",             kKeyCodeP },
      { "Q",             kKeyCodeQ },
      { "R",             kKeyCodeR },
      { "S",             kKeyCodeS },
      { "T",             kKeyCodeT },
      { "U",             kKeyCodeU },
      { "V",             kKeyCodeV },
      { "W",             kKeyCodeW },
      { "X",             kKeyCodeX },
      { "Y",             kKeyCodeY },
      { "Z",             kKeyCodeZ },
      { "0",             kKeyCode0 },
      { "1",             kKeyCode1 },
      { "2",             kKeyCode2 },
      { "3",             kKeyCode3 },
      { "4",             kKeyCode4 },
      { "5",             kKeyCode5 },
      { "6",             kKeyCode6 },
      { "7",             kKeyCode7 },
      { "8",             kKeyCode8 },
      { "9",             kKeyCode9 },
      { "COMMA",         kKeyCodeComma },
      { "PERIOD",        kKeyCodePeriod },
      { "AT",            kKeyCodeAt },
      { "SLASH",         kKeyCodeSlash },
      { "SPACE",         kKeyCodeSpace },
      { "ENTER",         kKeyCodeNewline },
      { "TAB",           kKeyCodeTab },
      { "GRAVE",         kKeyCodeGrave },
      { "MINUS",         kKeyCodeMinus },
      { "EQUALS",        kKeyCodeEquals },
      { "LEFT_BRACKET",  kKeyCodeLeftBracket },
      { "RIGHT_BRACKET", kKeyCodeRightBracket },
      { "BACKSLASH",     kKeyCodeBackslash },
      { "SEMICOLON",     kKeyCodeSemicolon },
      { "APOSTROPHE",    kKeyCodeApostrophe },
      { "STAR",          kKeyCodeStar },
      { "POUND",         kKeyCodePound },
      { "PLUS",          kKeyCodePlus },
      { "DEL",           kKeyCodeDel },
};

/* the following is automatically generated by the 'gen-charmap.py' script
 * do not touch. the generation command was:
 *   gen-charmap.py qwerty2.kcm
 */

static const AKeyEntry  _qwerty2_keys[] =
{
   /* keycode                   base   caps    fn  caps+fn   number */

    { kKeyCodeA             ,   'a',   'A',   'a',    'A',   'a' },
    { kKeyCodeB             ,   'b',   'B',   'b',    'B',   'b' },
    { kKeyCodeC             ,   'c',   'C', 0x00e7, 0x00E7,   'c' },
    { kKeyCodeD             ,   'd',   'D',  '\'',   '\'',  '\'' },
    { kKeyCodeE             ,   'e',   'E',   '"', 0x0301,   '"' },
    { kKeyCodeF             ,   'f',   'F',   '[',    '[',   '[' },
    { kKeyCodeG             ,   'g',   'G',   ']',    ']',   ']' },
    { kKeyCodeH             ,   'h',   'H',   '<',    '<',   '<' },
    { kKeyCodeI             ,   'i',   'I',   '-', 0x0302,   '-' },
    { kKeyCodeJ             ,   'j',   'J',   '>',    '>',   '>' },
    { kKeyCodeK             ,   'k',   'K',   ';',    '~',   ';' },
    { kKeyCodeL             ,   'l',   'L',   ':',    '`',   ':' },
    { kKeyCodeM             ,   'm',   'M',   '%',   0x00,   '%' },
    { kKeyCodeN             ,   'n',   'N',  0x00, 0x0303,   'n' },
    { kKeyCodeO             ,   'o',   'O',   '+',    '+',   '+' },
    { kKeyCodeP             ,   'p',   'P',   '=', 0x00A5,   '=' },
    { kKeyCodeQ             ,   'q',   'Q',   '|', 0x0300,   '|' },
    { kKeyCodeR             ,   'r',   'R',   '`', 0x20AC,   '`' },
    { kKeyCodeS             ,   's',   'S',  '\\', 0x00DF,  '\\' },
    { kKeyCodeT             ,   't',   'T',   '{', 0x00A3,   '}' },
    { kKeyCodeU             ,   'u',   'U',   '_', 0x0308,   '_' },
    { kKeyCodeV             ,   'v',   'V',   'v',    'V',   'v' },
    { kKeyCodeW             ,   'w',   'W',   '~',    '~',   '~' },
    { kKeyCodeX             ,   'x',   'X',   'x',    'X',   'x' },
    { kKeyCodeY             ,   'y',   'Y',   '}', 0x00A1,   '}' },
    { kKeyCodeZ             ,   'z',   'Z',   'z',    'Z',   'z' },
    { kKeyCodeComma         ,   ',',   '<',   ',',    ',',   ',' },
    { kKeyCodePeriod        ,   '.',   '>',   '.', 0x2026,   '.' },
    { kKeyCodeAt            ,   '@',   '@',   '@', 0x2022,   '@' },
    { kKeyCodeSlash         ,   '/',   '?',   '?',    '?',   '/' },
    { kKeyCodeSpace         ,  0x20,  0x20,   0x9,    0x9,  0x20 },
    { kKeyCodeNewline       ,   0xa,   0xa,   0xa,    0xa,   0xa },
    { kKeyCode0             ,   '0',   ')',   ')',    ')',   '0' },
    { kKeyCode1             ,   '1',   '!',   '!',    '!',   '1' },
    { kKeyCode2             ,   '2',   '@',   '@',    '@',   '2' },
    { kKeyCode3             ,   '3',   '#',   '#',    '#',   '3' },
    { kKeyCode4             ,   '4',   '$',   '$',    '$',   '4' },
    { kKeyCode5             ,   '5',   '%',   '%',    '%',   '5' },
    { kKeyCode6             ,   '6',   '^',   '^',    '^',   '6' },
    { kKeyCode7             ,   '7',   '&',   '&',    '&',   '7' },
    { kKeyCode8             ,   '8',   '*',   '*',    '*',   '8' },
    { kKeyCode9             ,   '9',   '(',   '(',    '(',   '9' },
    { kKeyCodeTab           ,   0x9,   0x9,   0x9,    0x9,   0x9 },
    { kKeyCodeGrave         ,   '`',   '~',   '`',    '~',   '`' },
    { kKeyCodeMinus         ,   '-',   '_',   '-',    '_',   '-' },
    { kKeyCodeEquals        ,   '=',   '+',   '=',    '+',   '=' },
    { kKeyCodeLeftBracket   ,   '[',   '{',   '[',    '{',   '[' },
    { kKeyCodeRightBracket  ,   ']',   '}',   ']',    '}',   ']' },
    { kKeyCodeBackslash     ,  '\\',   '|',  '\\',    '|',  '\\' },
    { kKeyCodeSemicolon     ,   ';',   ':',   ';',    ':',   ';' },
    { kKeyCodeApostrophe    ,  '\'',   '"',  '\'',    '"',  '\'' },
};

static const AKeyCharmap  _default_charmap =
{
    _qwerty2_keys,
    51,
    "qwerty2"
};

/* Custom character map created with -charmap option. */
static AKeyCharmap android_custom_charmap = { 0 };

static const AKeyCharmap* android_charmap = &_default_charmap;

/* Checks if a character represents an end of the line.
 * Returns a non-zero value if ch is an EOL character. Returns
 * zero value if ch is not an EOL character.
*/
static int
kcm_is_eol(char ch) {
    // EOLs are 0, \r and \n chars.
    return ('\0' == ch) || ('\n' == ch) || ('\r' == ch);
}

/* Checks if a character represents a token separator.
 * Returns a non-zero value if ch is a token separator.
 * Returns zero value if ch is not a token separator.
*/
static int
kcm_is_token_separator(char ch) {
    // Spaces and tabs are the only separators allowed
    // between tokens in .kcm files.
    return (' ' == ch) || ('\t' == ch);
}

/* Checks if a character represents a path separator.
 * Returns a non-zero value if ch is a path separator.
 * Returns zero value if ch is not a path separator.
*/
static int
kcm_is_path_separator(char ch) {
#ifdef _WIN32
    return '/' == ch || '\\' == ch;
#else
    return '/' == ch;
#endif  // _WIN32
}

/* Skips space separators in a string.
 * str - string to advance past space separators.
 * Returns pointer to the first character in the string, that is
 * not a space separator. Note that this routine may return
 * pointer to EOL in case if all characters in the string were
 * space separators.
*/
static const char*
kcm_skip_spaces(const char* str) {
    while (!kcm_is_eol(*str) && kcm_is_token_separator(*str)) {
        str++;
    }
    return str;
}

/* Advances string to the first space separator character.
 * str - string to advance.
 * Returns pointer to the first space separator character in the string.
 * Note that this routine may return pointer to EOL in case if all
 * characters in the string were not space separators.
*/
static const char*
kcm_skip_non_spaces(const char* str) {
    while (!kcm_is_eol(*str) && !kcm_is_token_separator(*str)) {
        str++;
    }
    return str;
}

/* Gets first token from a string.
 * line - String to get token from. End of the string should be
 * determined using kcm_is_eol() routine.
 * token - String where to copy token. Token, copied to this
 * string will be zero-terminated. Note that buffer for the
 * token string must be large enough to fit token of any size.
 * max_token_len - character size of the buffer addressed by
 * the 'token' parameter.
 * Returns NULL if there were no tokens found in the string, or
 * a pointer to the line string, advanced past the found token.
*/
static const char*
kcm_get_token(const char* line, char* token, size_t max_token_len) {
    // Pass spaces and tabs.
    const char* token_starts = kcm_skip_spaces(line);
    // Advance to next space.
    const char* token_ends = kcm_skip_non_spaces(token_starts);
    // Calc token length
    size_t token_len = token_ends - token_starts;
    if ((0 == token_len) || (token_len >= max_token_len)) {
      return NULL;
    }
    memcpy(token, token_starts, token_len);
    token[token_len] = '\0';
    return token_ends;
}

/* Checks if token represents a comment.
 * Returns non-zero value if token represents a comment, or zero otherwise.
*/
static int
kcm_is_token_comment(const char* token) {
    return '#' == *token;
}

/* Converts a key name to a key code as defined by AndroidKeyCode enum.
 * key_name - Key name to convert.
 * key_code - Upon success contains key code value for the key_name.
 * Returns a zero value on success, or -1 if key code was not found
 * for the given key_name.
*/
static int
kcm_get_key_code(const char* key_name, unsigned short* key_code) {
    int n;
    // Iterate through the key code map, matching key names.
    for (n = 0; n < sizeof(keycode_map) / sizeof(keycode_map[0]); n++) {
        if (0 == strcmp(key_name, keycode_map[n].key_name)) {
            *key_code = keycode_map[n].key_code;
            return 0;
        }
    }
    return -1;
}

/* Gets unsigned short hexadecimal value for a token.
 * token - Token to get hexadecimal value for. Note that this
 * routine expects a "clean" (i.e. no "0x" prefix) hex number
 * represented by the token string.
 * val - Upon success contains hexadecimal value for the token.
 * Returns a zero value on success, or -1 on error.
*/
static int
kcm_get_ushort_hex_val(const char* token, unsigned short* val) {
    int hex_val = hex2int((const uint8_t*)token, strlen(token));
    // Make sure token format was ok and value doesn't exceed unsigned short.
    if (-1 == hex_val || 0 != (hex_val & ~0xFFFF)) {
      return -1;
    }

    *val = (unsigned short)hex_val;

    return 0;
}

/* Gets a character or hexadecimal value represented by a token.
 * token - Token to get value from.
 * val - Upon success will contain a character or hexadecimal
 * value represented by a token.
 * Returns a zero value on success, or -1 on error.
*/
static int
kcm_get_char_or_hex_val(const char* token, unsigned short* val) {
    // For chars token must begin with ' followed by character followed by '
    if ('\'' == *token) {
        if ('\0' == token[1] || '\'' != token[2] || '\0' != token[3]) {
            return 0;
        }
        *val = token[1];
        return 0;
    } else {
        // Make sure that hex token is prefixed with "0x"
        if (('0' != *token) || ('x' != token[1])) {
            return -1;
        }
        // Past 0x
        return kcm_get_ushort_hex_val(token + 2, val);
    }
}

/* Gets first token for the line and calculates its value.
 * line - Line to get token's value from.
 * val - Upon success will contain a character or hexadecimal
 * value represented by the first token in the line.
 * returns NULL on error, or a pointer to the line string,
 * advanced past the found token.
*/
static const char*
kcm_get_char_or_hex_token_value(const char* line, unsigned short* val) {
    char token[KCM_MAX_TOKEN_LEN];
    line = kcm_get_token(line, token, KCM_MAX_TOKEN_LEN);
    if (NULL != line) {
        // Token must be a char, or a hex number.
        if (kcm_get_char_or_hex_val(token, val)) {
            return NULL;
        }
    }

    return line;
}

/* Parses a line in .kcm file extracting key information.
 * line - Line in .kcm file to parse.
 * line_index - Index of the parsing line in .kcm file.
 * key_entry - Upon success contains key information extracted from
 * the line.
 * kcm_file_path - Path to the charmap file, where paresed line was taken from.
 * returns BAD_FORMAT if line format was not recognized, SKIP_LINE if line
 * format was ok, but it didn't contain key information, or KEY_ENTRY
 * if key information was successfuly extracted from the line.
*/
static ParseStatus
kcm_parse_line(const char* line,
               int line_index,
               AKeyEntry* key_entry,
               const char* kcm_file_path) {
      char token[KCM_MAX_TOKEN_LEN];
      unsigned short disp;

      // Get first token, and see if it's an empty, or a comment line.
      line = kcm_get_token(line, token, KCM_MAX_TOKEN_LEN);
      if ((NULL == line) || kcm_is_token_comment(token)) {
          // Empty line, or a comment.
          return SKIP_LINE;
      }

      // Here we expect either [type=XXXX], or a key string.
      if ('[' == token[0]) {
          return SKIP_LINE;
      }

      // It must be a key string.
      // First token is key code.
      if (kcm_get_key_code(token, &key_entry->code)) {
          derror("Invalid format of charmap file %s. Unknown key %s in line %d",
                 kcm_file_path, token, line_index);
          return BAD_FORMAT;
      }

      // 2-nd token is display character, which is ignored.
      line = kcm_get_char_or_hex_token_value(line, &disp);
      if (NULL == line) {
          derror("Invalid format of charmap file %s. Invalid display value in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }

      // 3-rd token is number.
      line = kcm_get_char_or_hex_token_value(line, &key_entry->number);
      if (NULL == line) {
          derror("Invalid format of charmap file %s. Invalid number value in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }

      // 4-th token is base.
      line = kcm_get_char_or_hex_token_value(line, &key_entry->base);
      if (NULL == line) {
          derror("Invalid format of charmap file %s. Invalid base value in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }

      // 5-th token is caps.
      line = kcm_get_char_or_hex_token_value(line, &key_entry->caps);
      if (NULL == line) {
          derror("Invalid format of charmap file %s. Invalid caps value in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }

      // 6-th token is fn.
      line = kcm_get_char_or_hex_token_value(line, &key_entry->fn);
      if (NULL == line) {
          derror("Invalid format of charmap file %s. Invalid fn value in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }

      // 7-th token is caps_fn.
      line = kcm_get_char_or_hex_token_value(line, &key_entry->caps_fn);
      if (NULL == line) {
          derror("Invalid format of charmap file %s. Invalid caps_fn value in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }

      // Make sure that line doesn't contain anything else,
      // except (may be) a comment token.
      line = kcm_get_token(line, token, KCM_MAX_TOKEN_LEN);
      if ((NULL == line) || kcm_is_token_comment(token)) {
          return KEY_ENTRY;
      } else {
          derror("Invalid format of charmap file %s in line %d",
                 kcm_file_path, line_index);
          return BAD_FORMAT;
      }
}

void
kcm_extract_charmap_name(const char* kcm_file_path,
                         char* charmap_name,
                         int max_len) {
    const char* ext_separator;
    size_t to_copy;

    // Initialize charmap name with name of .kcm file.
    // First, get file name from the full path to .kcm file.
    const char* file_name = kcm_file_path + strlen(kcm_file_path);
    while (!kcm_is_path_separator(*file_name) &&
           (file_name != kcm_file_path)) {
        file_name--;
    }
    if (kcm_is_path_separator(*file_name)) {
        file_name++;
    }

    // Cut off file name extension.
    ext_separator = strrchr(file_name, '.');
    if (NULL == ext_separator) {
      // "filename" is legal name.
      ext_separator = file_name + strlen(file_name);
    } else if (ext_separator == file_name) {
      // ".filename" is legal name too. In this case we will use
      // "filename" as our custom charmap name.
      file_name++;
      ext_separator = file_name + strlen(file_name);
    }

    // Copy file name to charmap name.
    to_copy = ext_separator - file_name;
    if (to_copy > (max_len - 1)) {
        to_copy = max_len - 1;
    }
    memcpy(charmap_name, file_name, to_copy);
    charmap_name[to_copy] = '\0';
}

/* Extracts charmap name from .kcm file name,
 * and saves it into char_map as its name.
*/
static void
kcm_get_charmap_name(const char* kcm_file_path, AKeyCharmap* char_map) {
    kcm_extract_charmap_name(kcm_file_path, char_map->name,
                             sizeof(char_map->name));
}

/* Parses .kcm file producing key characters map.
 * See comments to this module for .kcm file format information.
 * This routine checks format only for character map lines. It will not check
 * format for empty lines, comments, and type section lines.
 * Note that line length in .kcm file should not exceed 1024 characters,
 * including newline character.
 *
 * Parameters:
 * kcm_file_path - Full path to the .kcm file to parse.
 * char_map - Upon success will contain initialized characters map.
 * Returns a zero value on success, or -1 on failure.
*/
static int
parse_kcm_file(const char* kcm_file_path, AKeyCharmap* char_map) {
    // A line read from .kcm file.
    char line[KCM_MAX_LINE_LEN];
    // Return code.
    int err = 0;
    // Number of the currently parsed line.
    int cur_line = 1;
    // Initial size of the charmap's array of keys.
    int map_size = 52;
    FILE* kcm_file;

    char_map->num_entries = 0;
    char_map->entries = 0;

    kcm_file = fopen(kcm_file_path, "r");
    if (NULL == kcm_file) {
        derror("Unable to open charmap file %s : %s",
               kcm_file_path, strerror(errno));
        return -1;
    }

    // Calculate charmap name.
    kcm_get_charmap_name(kcm_file_path, char_map);

    // Preallocate map.
    char_map->num_entries = 0;
    AARRAY_NEW0(char_map->entries, map_size);

    // Line by line parse the file.
    for (; 0 != fgets(line, sizeof(line), kcm_file); cur_line++) {
        AKeyEntry key_entry;
        ParseStatus parse_res =
            kcm_parse_line(line, cur_line, &key_entry, kcm_file_path);
        if (BAD_FORMAT == parse_res) {
            err = -1;
            break;
        } else if (KEY_ENTRY == parse_res) {
            AKeyEntry* entries;
            // Key information has been extracted. Add it to the map.
            // Lets see if we need to reallocate map.
            if (map_size == char_map->num_entries) {
                AKeyEntry* entries = (AKeyEntry*)char_map->entries;
                map_size += 10;
                AARRAY_RENEW(entries, map_size);
                char_map->entries = (const AKeyEntry*)entries;
            }
            entries = (AKeyEntry*)char_map->entries;
            entries[char_map->num_entries] = key_entry;
            char_map->num_entries++;
        }
    }

    if (!err) {
        // Make sure we exited the loop on EOF condition. Any other
        // condition is an error.
        if (0 == feof(kcm_file)) {
            err = -1;
        }
        if (err) {
          derror("Error reading charmap file %s : %s",
                  kcm_file_path, strerror(errno));
        }
    }

    fclose(kcm_file);

    if (err) {
        // Cleanup on failure.
        if (0 != char_map->entries) {
            AFREE((void*)char_map->entries);
            char_map->entries = 0;
        }
        char_map->num_entries = 0;
    }

    return err;
}

int
android_charmap_setup(const char* kcm_file_path) {

    /* Return if we already loaded a charmap */
    if (android_charmap != &_default_charmap || kcm_file_path == NULL)
        return 0;

    if (!parse_kcm_file(kcm_file_path, &android_custom_charmap)) {
        // Here we have the default charmap and the custom one.
        android_charmap = &android_custom_charmap;
    } else {
        derror("Unable to parse kcm file.");
        return -1;
    }

    return 0;
}

void
android_charmap_done(void) {
    if (android_charmap != &_default_charmap)
        AFREE((void*)android_charmap->entries);
}

const AKeyCharmap*
android_get_charmap_by_name(const char* name) {
    if (name != NULL) {
        if (!strcmp(android_charmap->name, name))
            return android_charmap;
        if (!strcmp(_default_charmap.name, name))
            return &_default_charmap;
    }
    return NULL;
}

int
android_charmap_reverse_map_unicode(const AKeyCharmap* cmap,
                                    unsigned int unicode,
                                    int  down,
                                    AKeycodeBuffer* keycodes)
{
    int                 n;

    if (unicode == 0)
        return 0;

    /* check base keys */
    for (n = 0; n < cmap->num_entries; n++) {
        if (cmap->entries[n].base == unicode) {
            android_keycodes_add_key_event(keycodes, cmap->entries[n].code, down);
            return 1;
        }
    }

    /* check caps + keys */
    for (n = 0; n < cmap->num_entries; n++) {
        if (cmap->entries[n].caps == unicode) {
            if (down) {
                android_keycodes_add_key_event(keycodes, kKeyCodeCapLeft, down);
            }
            android_keycodes_add_key_event(keycodes, cmap->entries[n].code, down);
            if (!down) {
                android_keycodes_add_key_event(keycodes, kKeyCodeCapLeft, down);
            }
            return 2;
        }
    }

    /* check fn + keys */
    for (n = 0; n < cmap->num_entries; n++) {
        if (cmap->entries[n].fn == unicode) {
            if (down) {
                android_keycodes_add_key_event(keycodes, kKeyCodeAltLeft, down);
            }
            android_keycodes_add_key_event(keycodes, cmap->entries[n].code, down);
            if (!down) {
                android_keycodes_add_key_event(keycodes, kKeyCodeAltLeft, down);
            }
            return 2;
        }
    }

    /* check caps + fn + keys */
    for (n = 0; n < cmap->num_entries; n++) {
        if (cmap->entries[n].caps_fn == unicode) {
            if (down) {
                android_keycodes_add_key_event(keycodes, kKeyCodeAltLeft, down);
                android_keycodes_add_key_event(keycodes, kKeyCodeCapLeft, down);
            }
            android_keycodes_add_key_event(keycodes, cmap->entries[n].code, down);
            if (!down) {
                android_keycodes_add_key_event(keycodes, kKeyCodeCapLeft, down);
                android_keycodes_add_key_event(keycodes, kKeyCodeAltLeft, down);
            }
            return 3;
        }
    }

    /* no match */
    return 0;
}

const AKeyCharmap* android_get_default_charmap(void)
{
    return &_default_charmap;
}

const AKeyCharmap* android_get_charmap(void)
{
    return android_charmap;
}

const char* android_get_charmap_name(void)
{
    return android_get_charmap()->name;
}
