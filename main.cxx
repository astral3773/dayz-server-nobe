#define NOMINMAX
#include <Windows.h>
#include <Zydis/Zydis.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <print>
#include <span>
#include <stdint.h>
#include <stddef.h>
#include <string_view>
#include <system_error>
#include <vector>

struct image_section_t {
    std::span<const uint8_t> data;
    uint32_t rva;
    size_t offset;
};

struct image_layout_t {
    uint64_t image_base;
    image_section_t text;
    image_section_t rdata;
};

struct patch_target_t {
    size_t offset;
    uint64_t address;
    uint8_t length;
    ZydisRegister reg;
};

std::optional<image_layout_t> parse_image(std::span<const uint8_t> image) {
    const auto read_header = [image]<typename T>(size_t offset, T& header) {
        if (offset > image.size() || sizeof(T) > image.size() - offset) {
            return false;
        }

        std::memcpy(&header, image.data() + offset, sizeof(T));
        return true;
    };

    IMAGE_DOS_HEADER dos{};
    if (!read_header(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        return {};
    }

    const auto nt_offset = static_cast<size_t>(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt{};
    if (!read_header(nt_offset, nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        return {};
    }

    image_layout_t layout{nt.OptionalHeader.ImageBase, {}, {}};
    const auto sections_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt.FileHeader.SizeOfOptionalHeader;

    for (size_t index = 0; index < nt.FileHeader.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER section{};
        if (!read_header(sections_offset + index * sizeof(section), section)) {
            return {};
        }

        const size_t offset = section.PointerToRawData;
        const size_t size = section.Misc.VirtualSize == 0 ? section.SizeOfRawData :
            std::min(section.SizeOfRawData, section.Misc.VirtualSize);
        if (offset > image.size() || size > image.size() - offset) {
            return {};
        }

        const auto name = std::string_view(reinterpret_cast<const char*>(section.Name), sizeof(section.Name));
        const image_section_t entry{image.subspan(offset, size), section.VirtualAddress, offset};
        if (name == std::string_view(".text\0\0\0", 8)) {
            if (!layout.text.data.empty()) {
                return {};
            }
            layout.text = entry;
        } else if (name == std::string_view(".rdata\0\0", 8)) {
            if (!layout.rdata.data.empty()) {
                return {};
            }
            layout.rdata = entry;
        }
    }

    if (layout.text.data.empty() || layout.rdata.data.empty()) {
        return {};
    }

    return layout;
}

std::vector<uint64_t> find_string_in_image(const image_layout_t& image, std::string_view string) {
    std::vector<uint64_t> matches;
    const auto& section = image.rdata;
    if (string.empty() || string.size() >= section.data.size()) {
        return matches;
    }

    for (size_t offset = 0; offset < section.data.size() - string.size(); ++offset) {
        if (std::memcmp(section.data.data() + offset, string.data(), string.size()) == 0 &&
            section.data[offset + string.size()] == 0) {
            matches.push_back(image.image_base + section.rva + offset);
        }
    }

    return matches;
}

std::vector<std::optional<patch_target_t>> find_xrefs(const image_layout_t& image, uint64_t string_address) {
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    const auto& section = image.text;
    std::vector<std::optional<patch_target_t>> matches;
    std::optional<patch_target_t> last_test;

    for (size_t offset = 0; offset < section.data.size();) {
        ZydisDecodedInstruction instruction{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, section.data.data() + offset,
            section.data.size() - offset, &instruction, operands))) {
            last_test.reset();
            ++offset;
            continue;
        }

        const uint64_t address = image.image_base + section.rva + offset;
        bool references_string = false;
        for (size_t index = 0; index < instruction.operand_count_visible; ++index) {
            const auto& operand = operands[index];
            uint64_t target = 0;
            if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY ||
                (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative)) {
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand, address, &target)) &&
                    target == string_address) {
                    references_string = true;
                }
            } else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.value.u == string_address) {
                references_string = true;
            }
        }

        if (references_string) {
            std::println("[+] xref: {:#x}", address);
            matches.push_back(last_test);
        }

        if (instruction.mnemonic == ZYDIS_MNEMONIC_TEST) {
            last_test.reset();
            if (instruction.operand_count_visible > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                last_test = patch_target_t{section.offset + offset, address, instruction.length, operands[0].reg.value};
            }
        }

        offset += instruction.length;
    }

    return matches;
}

bool patch_instruction(std::span<uint8_t> image, const patch_target_t& target) {
    ZydisEncoderRequest request{};
    request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    request.mnemonic = ZYDIS_MNEMONIC_CMP;
    request.operand_count = 2;
    request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
    request.operands[0].reg.value = target.reg;
    request.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    request.operands[1].imm.u = 2;

    std::array<uint8_t, ZYDIS_MAX_INSTRUCTION_LENGTH> encoded{};
    ZyanUSize length = encoded.size();
    if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&request, encoded.data(), &length))) {
        std::println("[-] unable to encode cmp");
        return false;
    }

    if (length > target.length) {
        std::println("[-] cmp needs {} bytes; test only has {} bytes", length, target.length);
        return false;
    }

    if (target.offset > image.size() || target.length > image.size() - target.offset) {
        return false;
    }

    auto destination = image.subspan(target.offset, target.length);
    std::fill(destination.begin(), destination.end(), uint8_t{0x90});
    std::copy_n(encoded.begin(), length, destination.begin());
    std::println("[+] patched test at {:#x} to cmp {}, 2", target.address, ZydisRegisterGetString(target.reg));
    return true;
}

int main() {
    const std::filesystem::path input_path = "DayZServer_x64.exe";
    const std::filesystem::path backup_path = "DayZServer_x64.bak";

    std::ifstream file(input_path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::println("[-] unable to open DayZServer_x64.exe");
        getchar();
        return 1;
    }

    const auto size = file.tellg();
    if (size <= 0) {
        std::println("[-] unable to get image size");
        getchar();
        return 1;
    }

    std::vector<uint8_t> image_data(static_cast<size_t>(size));
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(image_data.data()), static_cast<std::streamsize>(image_data.size()))) {
        std::println("[-] unable to read image");
        getchar();
        return 1;
    }
    file.close();

    const auto image = parse_image(image_data);
    if (!image) {
        std::println("[-] expected an x64 PE image with .text and .rdata");
        getchar();
        return 1;
    }

    const auto strings = find_string_in_image(*image, "BattlEye initialization failed");
    if (strings.size() != 1) {
        std::println("[-] expected exactly one matching string in .rdata");
        getchar();
        return 1;
    }
    std::println("[+] string: {:#x}", strings.front());

    const auto xrefs = find_xrefs(*image, strings.front());
    if (xrefs.size() != 1 || !xrefs.front()) {
        std::println("[-] expected one xref with a preceding register test");
        getchar();
        return 1;
    }

    std::error_code error;
    std::filesystem::copy_file(input_path, backup_path, std::filesystem::copy_options::overwrite_existing, error);
    if (error) {
        std::println("[-] unable to back up original image");
        getchar();
        return 1;
    }

    std::ifstream backup(backup_path, std::ios::binary | std::ios::ate);
    if (!backup || backup.tellg() != size) {
        std::println("[-] backup does not match the original image");
        getchar();
        return 1;
    }
    std::vector<uint8_t> backup_data(image_data.size());
    backup.seekg(0);
    if (!backup.read(reinterpret_cast<char*>(backup_data.data()), static_cast<std::streamsize>(backup_data.size())) ||
        backup_data != image_data) {
        std::println("[-] backup does not match the original image");
        getchar();
        return 1;
    }
    backup.close();

    const auto& target = *xrefs.front();
    if (!patch_instruction(image_data, target)) {
        std::println("[-] unable to patch instruction without overwriting adjacent code");
        getchar();
        return 1;
    }

    std::fstream output(input_path, std::ios::binary | std::ios::in | std::ios::out);
    if (!output) {
        std::println("[-] unable to open original image for patching");
        getchar();
        return 1;
    }
    output.seekp(static_cast<std::streamoff>(target.offset));
    output.write(reinterpret_cast<const char*>(image_data.data() + target.offset), target.length);
    output.close();
    if (!output) {
        std::println("[-] unable to write patch; restore the original from DayZServer_x64.bak");
        getchar();
        return 1;
    }

    std::println("[+] patched {}", input_path.string());

    const std::filesystem::path battleye_path = "battleye";
    const std::filesystem::path renamed_path = "nbattleye";
    const bool battleye_exists = std::filesystem::exists(battleye_path, error);
    if (error) {
        std::println("[-] unable to check battleye folder");
        getchar();
        return 1;
    }

    if (battleye_exists) {
        if (!std::filesystem::is_directory(battleye_path, error) || error) {
            std::println("[-] battleye is not an accessible folder");
            getchar();
            return 1;
        }
        if (std::filesystem::exists(renamed_path, error) || error) {
            std::println("[-] nbattleye already exists or cannot be checked");
            getchar();
            return 1;
        }

        std::filesystem::rename(battleye_path, renamed_path, error);
        if (error) {
            std::println("[-] unable to rename battleye folder");
            getchar();
            return 1;
        }
        std::println("[+] renamed battleye to nbattleye");
    }

    const std::filesystem::path config_path = "serverDZ.cfg";
    const std::filesystem::path config_backup_path = "serverDZ.bak";
    std::filesystem::copy_file(config_path, config_backup_path, std::filesystem::copy_options::overwrite_existing, error);
    if (error) {
        std::println("[-] unable to back up serverDZ.cfg");
        getchar();
        return 1;
    }

    std::ofstream config(config_path, std::ios::app);
    if (!config) {
        std::println("[-] unable to open serverDZ.cfg");
        getchar();
        return 1;
    }
    config << "\ndisableVAC = 1;             // Allows players to connect with vac/game bans\n";
    config.close();
    if (!config) {
        std::println("[-] unable to write serverDZ.cfg; restore it from serverDZ.bak");
        getchar();
        return 1;
    }
    std::println("[+] updated serverDZ.cfg");

    return 0;
}
