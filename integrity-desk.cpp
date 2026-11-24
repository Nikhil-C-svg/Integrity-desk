#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using Snapshot = std::map<std::string, std::string>;
constexpr char manifestHeader[] = "INTEGRITY-DESK SHA256 1";
constexpr char hexDigits[] = "0123456789abcdef";

void check(NTSTATUS status) {
    if (status < 0) throw std::runtime_error("Windows CNG could not compute SHA-256.");
}

class Sha256 {
public:
    Sha256() {
        check(BCryptOpenAlgorithmProvider(&provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
    }
    ~Sha256() { BCryptCloseAlgorithmProvider(provider, 0); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    std::string file(const fs::path& path) const {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("Cannot open: " + path.u8string());

        struct Hash {
            BCRYPT_HASH_HANDLE handle = nullptr;
            ~Hash() { if (handle) BCryptDestroyHash(handle); }
        } hash;
        check(BCryptCreateHash(provider, &hash.handle, nullptr, 0, nullptr, 0, 0));
        std::array<unsigned char, 65536> buffer{};
        for (;;) {
            input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            const auto size = static_cast<ULONG>(input.gcount());
            if (size) check(BCryptHashData(hash.handle, buffer.data(), size, 0));
            if (input.bad()) throw std::runtime_error("Cannot read: " + path.u8string());
            if (input.eof()) break;
            if (!input) throw std::runtime_error("Cannot read: " + path.u8string());
        }

        std::array<unsigned char, 32> digest{};
        check(BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0));
        std::string hex;
        for (auto byte : digest) {
            hex += hexDigits[byte >> 4];
            hex += hexDigits[byte & 15];
        }
        return hex;
    }

private:
    BCRYPT_ALG_HANDLE provider = nullptr;
};

Snapshot scan(const fs::path& root) {
    Snapshot result;
    const Sha256 sha256;
    for (auto it = fs::recursive_directory_iterator(root);
         it != fs::recursive_directory_iterator(); ++it) {
        const auto& path = it->path();
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            throw std::runtime_error("Cannot inspect: " + path.u8string());
        }
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            it.disable_recursion_pending();
            continue;
        }
        if (it->is_regular_file()) {
            result.emplace(path.lexically_relative(root).generic_u8string(), sha256.file(path));
        }
    }
    return result;
}

bool inside(const fs::path& parent, const fs::path& child) {
    auto component = child.begin();
    for (const auto& part : parent) {
        if (component == child.end() ||
            CompareStringOrdinal(part.c_str(), -1, component->c_str(), -1, TRUE) != CSTR_EQUAL) {
            return false;
        }
        ++component;
    }
    return true;
}

std::ifstream openInput(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open: " + path.u8string());
    return input;
}

void writeNew(const fs::path& path, const std::string& contents) {
    // Stage in the destination directory so publishing never overwrites an existing file.
    wchar_t temporary[MAX_PATH]{};
    if (!GetTempFileNameW(path.parent_path().c_str(), L"int", 0, temporary)) {
        throw std::runtime_error("Cannot create a temporary file beside the output.");
    }
    struct TemporaryFile {
        const wchar_t* path;
        ~TemporaryFile() { if (path) DeleteFileW(path); }
    } cleanup{temporary};
    std::ofstream output(fs::path{temporary}, std::ios::binary | std::ios::trunc);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.close();
    if (!output) throw std::runtime_error("Cannot write output: " + path.u8string());
    if (!MoveFileExW(temporary, path.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("Cannot publish output. Check permissions or use a fresh filename.");
    }
    cleanup.path = nullptr;
}

std::string serialize(const Snapshot& snapshot) {
    std::ostringstream output;
    output << manifestHeader << '\n';
    for (const auto& [name, hash] : snapshot) {
        output << hash << ' ' << std::quoted(name) << '\n';
    }
    return output.str();
}

Snapshot readBaseline(const fs::path& path) {
    auto input = openInput(path);
    std::string line;
    if (!std::getline(input, line) || line != manifestHeader) {
        throw std::runtime_error("Unsupported baseline header.");
    }
    Snapshot result;
    while (std::getline(input, line)) {
        if (line.size() < 68 || line[64] != ' ' || line[65] != '"') {
            throw std::runtime_error("Malformed baseline entry.");
        }
        const auto hash = line.substr(0, 64);
        std::istringstream field(line.substr(65));
        std::string name;
        if (hash.find_first_not_of(hexDigits) != std::string::npos ||
            !(field >> std::quoted(name)) || name.empty() ||
            field.peek() != std::char_traits<char>::eof() ||
            !result.emplace(name, hash).second) {
            throw std::runtime_error("Malformed or duplicate baseline entry.");
        }
    }
    if (input.bad()) throw std::runtime_error("Cannot read baseline.");
    return result;
}

std::string jsonString(const std::string& value) {
    std::string result = "\"";
    for (unsigned char byte : value) {
        if (byte == '"' || byte == '\\') {
            result += '\\';
            result += static_cast<char>(byte);
        } else if (byte < 32 || byte == '<' || byte == '>' || byte == '&') {
            // In an HTML script element, literal '<' could start a closing tag.
            result += "\\u00";
            result += hexDigits[byte >> 4];
            result += hexDigits[byte & 15];
        } else {
            result += static_cast<char>(byte);
        }
    }
    return result + '"';
}

struct Audit {
    std::string json;
    std::size_t changes = 0;
};

Audit compare(const Snapshot& before, const Snapshot& after) {
    Audit result{"{\"sample\":false,\"rows\":["};
    bool first = true;
    auto row = [&](const std::string& name, const char* status,
                   const std::string& oldHash, const std::string& newHash) {
        if (!first) result.json += ',';
        first = false;
        result.json += '[' + jsonString(name) + ',' + jsonString(status) +
                       ',' + jsonString(oldHash) + ',' + jsonString(newHash) + ']';
    };
    for (const auto& [name, hash] : before) {
        const auto current = after.find(name);
        if (current == after.end()) {
            row(name, "Removed", hash, "");
            ++result.changes;
        } else if (current->second != hash) {
            row(name, "Modified", hash, current->second);
            ++result.changes;
        } else {
            row(name, "Unchanged", hash, hash);
        }
    }
    for (const auto& [name, hash] : after) {
        if (before.count(name) == 0) {
            row(name, "Added", "", hash);
            ++result.changes;
        }
    }
    result.json += "]}";
    return result;
}

std::string render(const fs::path& layout, const std::string& data) {
    auto input = openInput(layout);
    std::string html((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const std::string opening = "<script id=\"audit-data\" type=\"application/json\">";
    const auto marker = html.find(opening);
    if (marker == std::string::npos) throw std::runtime_error("Missing dashboard data marker.");
    const auto start = marker + opening.size();
    const auto end = html.find("</script>", start);
    if (end == std::string::npos) throw std::runtime_error("Incomplete dashboard data marker.");
    html.replace(start, end - start, data);
    return html;
}

int wmain(int argc, wchar_t** argv) {
    const std::wstring command = argc > 1 ? argv[1] : L"";
    const bool snapshot = command == L"snapshot" && argc == 4;
    const bool audit = command == L"audit" && argc == 6;
    if (!snapshot && !audit) {
        std::cerr << "Usage:\n"
                  << "  integrity-desk snapshot <folder> <baseline>\n"
                  << "  integrity-desk audit <folder> <baseline> <index.html> <report.html>\n";
        return 1;
    }

    try {
        const auto root = fs::canonical(argv[2]);
        if (!fs::is_directory(root)) throw std::runtime_error("Scan target must be a folder.");
        const auto baseline = fs::weakly_canonical(fs::absolute(argv[3]));
        if (inside(root, baseline)) throw std::runtime_error("Keep the baseline outside the scan folder.");
        if (snapshot) {
            const auto files = scan(root);
            writeNew(baseline, serialize(files));
            std::cout << files.size() << " file(s) added to the baseline.\n";
            return 0;
        }

        const auto report = fs::weakly_canonical(fs::absolute(argv[5]));
        if (inside(root, report)) throw std::runtime_error("Keep the report outside the scan folder.");
        const auto before = readBaseline(baseline);
        const auto findings = compare(before, scan(root));
        writeNew(report, render(argv[4], findings.json));
        std::cout << findings.changes << " change(s). Open the HTML report in your browser.\n";
        return findings.changes ? 2 : 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
                                                                                                                                                                                                                                                                                                                                                      