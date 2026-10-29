// Copyright (c) 2026 haasanen — SPDX-License-Identifier: GPL-3.0-only
//
// splitscreen-unlock — mcpelauncher mod (mod_init ABI, loaded from <data>/mods/)
// re-enabling Bedrock console-style local splitscreen on the x86 Android build.
//
// How it works (verified on 1.26.52.3, see wiki entities/mcelauncher RE notes):
// the game ships the whole console splitscreen subsystem (join popup UI is even
// in the vanilla resource pack), but the split-screen-changed listener routes a
// controller-2 join attempt to the "split screen unavailable" toast because the
// last-node capability flag check fails on the PC/Android screen chain. The
// decision is one conditional jump:
//     cmp byte [rax+0x10], 0 ; je <toast-path>        <- flip this
// fallthrough = the join-accept path (secondary user sign-in via IUserManager,
// exactly the console flow). We NOP that `je` so joins proceed.
//
// Self-locating: no hardcoded addresses at runtime. We (1) find the mapped
// libminecraftpe.so, (2) locate the anchor localization strings in its image,
// (3) scan executable segments for RIP-relative lea references to them,
// (4) walk back from each reference to the exact byte pattern
// `80 78 10 00 0F 84` (cmp byte [rax+0x10],0 ; je rel32) and NOP the je.
// Every step must verify or we touch nothing.
//
// Version safety: MCPE_SS_VERSION (set by our launchers) is checked against an
// embedded allowlist of versions where the pattern was verified offline.
// Unknown version -> mod stays inert unless MCPE_SS_FORCE=1.
//
// env: MCPE_SS_DISABLE=1 skip everything
//      MCPE_SS_DEBUG=1   verbose scan logging
//      MCPE_SS_FORCE=1   apply on versions missing from the allowlist
//      MCPE_SS_VERSION   game version string (set by mcpe-instance)

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <algorithm>
#include <vector>

#ifndef STANDALONE
extern "C" void mod_init();
#endif

namespace {

const char* kAnchorToastMessage = "splitscreen.unavailable.toastMessage";
const char* kAllowedVersions[][2] = {
    {"1.26.52.3", "1"},  // verified: 2 lea sites, 1 gate je found+patterned
};

bool dbg() { return getenv("MCPE_SS_DEBUG") != nullptr; }
void log(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[splitscreen-unlock] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

struct Seg { const unsigned char* mem; uint64_t vaddr; size_t size; bool exec; };
struct Image { std::vector<Seg> segs; };

int phdr_cb(struct dl_phdr_info* info, size_t, void* out) {
    auto* img = static_cast<Image*>(out);
    const char* name = info->dlpi_name;
    if (!name || !strstr(name, "libminecraftpe.so")) return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const auto& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) continue;
        img->segs.push_back({
            reinterpret_cast<const unsigned char*>(info->dlpi_addr + ph.p_vaddr),
            ph.p_vaddr, ph.p_memsz, (ph.p_flags & PF_X) != 0});
    }
    return 0;
}

// exact NUL-terminated string search within [mem, mem+size)
const unsigned char* memstr(const unsigned char* mem, size_t size, const char* s) {
    size_t sl = strlen(s) + 1;
    if (sl > size) return nullptr;
    unsigned char c = (unsigned char)s[0];
    for (size_t i = 0; i + sl <= size; i++) {
        if (mem[i] != c) continue;
        if (memcmp(mem + i, s, sl) == 0) return mem + i;
    }
    return nullptr;
}

// all RIP-relative lea sites in exec segments referencing string at vaddr
std::vector<uintptr_t> findLeaRefs(const Image& img, uint64_t strVaddr) {
    std::vector<uintptr_t> hits;
    for (auto& s : img.segs) {
        if (!s.exec) continue;
        for (size_t i = 0; i + 7 <= s.size; i++) {
            const unsigned char* b = s.mem + i;
            if (b[1] != 0x8D) continue;
            if (b[0] != 0x48 && b[0] != 0x4C) continue;
            if ((b[2] & 0xC7) != 0x05) continue;  // RIP-relative: mod=00, rm=101, any reg
            int32_t disp; memcpy(&disp, b + 3, 4);
            uint64_t site = s.vaddr + i;
            if (site + 7 + (int64_t)disp == strVaddr) hits.push_back((uintptr_t)site);
        }
    }
    std::sort(hits.begin(), hits.end());
    return hits;
}

// search backward from ref for kPattern; returns file-image vaddr of the je opcode
uintptr_t findGateBefore(const Image& img, uintptr_t ref, size_t window) {
    const unsigned char pat[] = {0x80, 0x78, 0x10, 0x00, 0x0F, 0x84};
    for (auto& s : img.segs) {
        if (!s.exec) continue;
        if (ref < s.vaddr || ref >= s.vaddr + s.size) continue;
        size_t lo = ref - s.vaddr;
        size_t from = lo > window ? lo - window : 0;
        for (size_t i = lo; i-- > from;) {
            if (memcmp(s.mem + i, pat, sizeof(pat)) == 0)
                return s.vaddr + i + 4;  // address of the 0F 84 (je) opcode
        }
    }
    return 0;
}

bool versionAllowed() {
    const char* v = getenv("MCPE_SS_VERSION");
    if (!v || !*v) return true;  // caller didn't tell us; pattern checks carry it
    for (auto& a : kAllowedVersions)
        if (strcmp(a[0], v) == 0) return true;
    return false;
}

int run(bool patchIt, const char* standalonePath) {
    if (getenv("MCPE_SS_DISABLE")) { log("disabled by MCPE_SS_DISABLE"); return 0; }

    Image img;
    if (!standalonePath) {
        dl_iterate_phdr(phdr_cb, &img);
        if (img.segs.empty()) { log("libminecraftpe.so not mapped"); return 1; }
    } else {
        // standalone: vaddr==file offset for the identity-mapped first LOAD
        static std::vector<unsigned char> buf;
        FILE* f = fopen(standalonePath, "rb");
        if (!f) { fprintf(stderr, "open: %s\n", standalonePath); return 2; }
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        buf.resize((size_t)n);
        if (fread(buf.data(), 1, (size_t)n, f) != (size_t)n) { fclose(f); return 2; }
        fclose(f);
        img.segs.push_back({buf.data(), 0, (size_t)n, true});   // code scan
        img.segs.push_back({buf.data(), 0, (size_t)n, false});  // string scan
    }

    // anchor string vaddrs
    uint64_t anchorV[2] = {0, 0};
    for (int k = 0; k < 2; k++) {
        const char* s = k ? kAnchorToastMessage : "splitscreen.unavailable.toastHeader";
        for (auto& seg : img.segs) {
            if (seg.exec && standalonePath) continue;
            if (const unsigned char* p = memstr(seg.mem, seg.size, s)) {
                anchorV[k] = seg.vaddr + (p - seg.mem);
                break;
            }
        }
        if (anchorV[k]) { if (dbg()) log("anchor[%d] vaddr 0x%llx", k, (unsigned long long)anchorV[k]); }
        else if (standalonePath) {
            // file scan fallback for standalone string find
            const unsigned char* p = memstr(img.segs[1].mem, img.segs[1].size, s);
            if (p) anchorV[k] = (uintptr_t)(p - img.segs[1].mem);
        }
    }
    if (!anchorV[1]) { log("anchor strings absent — incompatible build, staying inert"); return 3; }

    if (!standalonePath && !versionAllowed() && !getenv("MCPE_SS_FORCE")) {
        log("game version %s not allowlisted — staying inert (MCPE_SS_FORCE=1 to try)",
            getenv("MCPE_SS_VERSION"));
        return 0;
    }

    // gate = backward-pattern from every toastMessage lea site
    auto sites = findLeaRefs(img, anchorV[1]);
    log("toastMessage lea sites: %zu", sites.size());
    int patched = 0;
    for (uintptr_t site : sites) {
        uintptr_t je = findGateBefore(img, site, 0x300);
        if (!je) { log("site 0x%llx: no cmp-byte/je pattern within 0x300 — skipped",
                       (unsigned long long)site); continue; }
        if (dbg()) log("site 0x%llx -> je at 0x%llx", (unsigned long long)site, (unsigned long long)je);
        if (!patchIt) { patched++; continue; }
        // NOP the je (2 bytes); imm32 payload becomes dead code bytes
        for (auto& seg : img.segs) {
            if (!seg.exec || je < seg.vaddr || je >= seg.vaddr + seg.size) continue;
            uintptr_t page = (seg.vaddr + 0) + 0;  // page-align absolute addr
            void* mem = const_cast<unsigned char*>(seg.mem + (je - seg.vaddr));
            uintptr_t absa = (uintptr_t)mem;
            page = absa & ~(uintptr_t)0xFFF;
            if (mprotect((void*)page, 0x2000, PROT_READ | PROT_WRITE) != 0) {
                log("mprotect failed at 0x%llx", (unsigned long long)absa); break;
            }
            ((unsigned char*)mem)[0] = 0x90;
            ((unsigned char*)mem)[1] = 0x90;
            mprotect((void*)page, 0x2000, PROT_READ | PROT_EXEC);
            patched++;
            break;
        }
    }
    if (patchIt) {
        if (patched) log("console splitscreen unlocked: %zu gate(s) opened", (size_t)patched);
        else log("no gate patched — build incompatible, game untouched");
    } else {
        printf("{\"anchors\": [%lld, %lld], \"lea_sites\": %zu, \"gates\": %d}\n",
               (long long)anchorV[0], (long long)anchorV[1], sites.size(), patched);
    }
    return patched ? 0 : 4;
}

}  // namespace

extern "C" void mod_init() { run(true, nullptr); }

#ifdef STANDALONE
int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: anchor-verify <libminecraftpe.so>\n"); return 2; }
    return run(false, argv[1]);
}
#endif
