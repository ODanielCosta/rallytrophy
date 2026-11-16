// Collision model constructor (0x419f30): filters triangles of a source mesh, welds vertices, builds the edge table.
#include <stdexcept>
#include <math.h>
#include <string.h>
#include "unk_419f00.h"
#include "unk_419f30.h"
#include "unk_414330.h"
#include "x87_cross.h"
#include <string>
struct CStr {
    std::allocator<char> alloc; char* ptr; unsigned int len; unsigned int res;
    bool Grow(unsigned int n, bool trim);
    void Eos(unsigned int n);
    CStr(const char* s, const std::allocator<char>& al = std::allocator<char>()) : alloc(al) {
        ptr = 0; len = 0; res = 0;
        unsigned int n = strlen(s);
        if (Grow(n, true)) { memcpy(ptr, s, n); Eos(n); }
    }
    ~CStr() {}
};
#pragma comment(linker, "/alternatename:?Grow@CStr@@QAE_NI_N@Z=?_Grow@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAE_NI_N@Z")
#pragma comment(linker, "/alternatename:?Eos@CStr@@QAEXI@Z=?_Eos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z")
struct ErrStr {
    std::allocator<char> alloc; char* ptr; unsigned int len; unsigned int res;
    void Assign(const CStr& x, unsigned int pos, unsigned int n);
    ErrStr(const CStr& x) : alloc(x.alloc) { ptr = 0; len = 0; res = 0; Assign(x, 0, std::string::npos); }
    ~ErrStr();
};
#pragma comment(linker, "/alternatename:?Assign@ErrStr@@QAEXABUCStr@@II@Z=?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@ABV12@II@Z")
class ColLogicError : public std::exception {
public:
    ColLogicError(const CStr& s) : std::exception(""), str(s) {}
    virtual ~ColLogicError();
    ErrStr str;
};

extern "C" void fun_004bd000(void* p);
extern float DAT_004e134c, DAT_004e1348;
extern int DAT_00508504, DAT_00508508, DAT_0050850c;

// Raw view of a ColTri (0x40 bytes).
struct ColTriRaw {
    float center[3], radius;     // 0x00 (bounding sphere)
    short id;                    // 0x10
    short pad12;
    int pad14;
    float n[3];                  // 0x18
    float d;                     // 0x24
    void* v[3];                  // 0x28
    int e[3];                    // 0x34
};
struct V3D { float x, y, z; float* Sub(float* out, const float* o) const; }; // 0x414330, returns its out pointer
struct DV3 { float v[3]; ~DV3() {} };
struct EdgeEnt { int lo, hi, id; };

// Local element types with user ctor+dtor so new[] goes through the EH vector-ctor helper.
struct LV { int pad; float x, y, z; LV() {} ~LV() {} };
struct LT { char pad[0x40]; LT() {} ~LT() {} };
struct LL { float x, y, z; LL() {} ~LL() {} };

// Edge-table insert, unrolled three times in the original (no k loop).
#define EDGE(K, LO, HI) { \
            EdgeEnt* e = (EdgeEnt*)(table + remap[LO] * 3); \
            int id; \
            while (1) { if (e->id == 0) break; if (e->lo == LO && e->hi == HI) break; e++; } \
            id = e->id; if (id == 0) { e->id = next; e->lo = LO; e->hi = HI; id = next++; } \
            tr->e[K] = id; }
// NONMATCHING: RALLYTROPHY 0x419f30
// reason: logic complete; original uses an ebp frame and 2386 vs 2510 bytes (register allocation differs); throw type/ctor arity (orig takes 1 stack arg) unverified
// 2026-11-13 pass (490 -> 362 insns differ, 2234 -> 2307 bytes): edge insert unrolled x3 with top-tested search + id=e->id; tri cursor; ternary min/max; tr=(ColTriRaw*)tris+i with ti2; int-register vertex copy; unrolled final e[] fixup via tris member.
// Pass 2026-11-16 (L1): wverts stored after tris alloc via W local, p2/p3/p1 y,z int-bit copies, *to triOk cursor, srcT loaded inside the || test, V3D Sub returns used by X87Cross, DAT_005085xx update order 04,08,0c: 362 -> 350 insns, 2307 -> 2345 bytes (orig 2386); open: tri loop keeps this/tris base in stack slots in the original, tri filter cursor (orig edi=tp, ours tp+8), mesh reload from [ebp+8] after first test.
// Tried 2026-11-01 re-pass: plain zeroing loops + no volatile mesh reload + volatile zero reg z improved 591->557 insns differ (2529->2489 bytes); memset, tri cursor, srcV hoist, z in loops, volatile p2.y/z all worse or equal; plateau far from 10 so no permuter.
// Tried 2026-10-31: memset zeroing, LV/LT/LL vector-ctor new[], volatile reload of the mesh param (VM), per-iteration verts reload, size CSE (630->591 insns); still differs: original keeps 0 in esi, frame 0x74 vs ours 0x80, and the tri-filter keeps p2.y/z in stack temps; Vec3-copy and EH-state variants all landed worse.
ColModel::ColModel(void* meshp, int)
{
    ColSrcMesh* mesh = (ColSrcMesh*)meshp;
    int z = 0;
    root = (TriNode*)z;
    int srcT0;
    if (mesh->nVerts == 0 || (srcT0 = mesh->nTris) == 0) {
        throw ColLogicError(CStr("missing collision model"));
    }
#define VM mesh
    int srcT = srcT0;
    pad24 = 1;
    nVerts = z;
    nTris = z;
    int* remap = new int[mesh->nVerts];
    int* triOk = new int[srcT];
    int i;
    memset(remap, 0, mesh->nVerts * 4);
    memset(triOk, 0, srcT * 4);
    ColSrcTri* st = VM->tris;
    ColSrcTri* tp = st;
    int* to = triOk;
    for (i = 0; i < srcT; i++, tp++, to++) {
        if (tp->obj->kind < 0x11) {
            int ic = tp->c, ib = tp->b, ia = tp->a;
            float* vb = VM->verts;
            S414Vec3* p2 = (S414Vec3*)(vb + ib * 3);
            S414Vec3* p1 = (S414Vec3*)(vb + ia * 3);
            S414Vec3* p3 = (S414Vec3*)(vb + ic * 3);
            int iy = ((int*)p2)[1], iz = ((int*)p2)[2];
            float ey = *(float*)&iy, ez = *(float*)&iz;
            float ex = p2->x - p1->x; ey -= p1->y; ez -= p1->z;
            if (ey * ey + ez * ez + ex * ex > DAT_004e134c) {
                iy = ((int*)p3)[1]; iz = ((int*)p3)[2];
                ey = *(float*)&iy; ez = *(float*)&iz;
                ex = p3->x - p2->x; ey -= p2->y; ez -= p2->z;
                if (ey * ey + ez * ez + ex * ex > DAT_004e134c) {
                    iy = ((int*)p1)[1]; iz = ((int*)p1)[2];
                    ey = *(float*)&iy; ez = *(float*)&iz;
                    ex = p1->x - p3->x; ey -= p3->y; ez -= p3->z;
                    if (ey * ey + ez * ez + ex * ex > DAT_004e134c) {
                        nTris++;
                        *to = 1;
                        remap[st[i].a] = 1;
                        remap[st[i].b] = 1;
                        remap[st[i].c] = 1;
                    }
                }
            }
        }
    }
    int next = 1;
    for (i = 0; i < VM->nVerts; i++) {
        if (remap[i] != 0) {
            remap[i] = next++;
            nVerts++;
        }
    }
    verts = (ColVert*)new LV[nVerts];
    ColVert* W = (ColVert*)new LV[nVerts];
    tris = (ColTri*)new LT[nTris];
    wverts = W;
    centers = (ColLocal*)new LL[nTris];
    for (i = 0; i < VM->nVerts; i++) {
        int id = remap[i];
        if (id != 0) {
            float* s = VM->verts + i * 3;
            ColVert* lv = &verts[id - 1];
            int* si = (int*)s; int* li = (int*)&lv->x;
            li[0] = si[0];
            li[1] = si[1];
            li[2] = si[2];
            lv->pad = 0;
            wverts[id - 1].x = *(float*)&li[0];
            wverts[id - 1].y = *(float*)&li[1];
            wverts[id - 1].z = *(float*)&li[2];
            wverts[id - 1].pad = 0;
        }
    }
    ColTriRaw* t = (ColTriRaw*)tris;
    int* ti = (int*)t;
    int k = 0;
    for (i = 0; i < srcT; i++) {
        if (triOk[i] != 0) {
            ti[k * 16 + 10] = remap[st[i].a] - 1;
            ti[k * 16 + 11] = remap[st[i].b] - 1;
            ti[k * 16 + 12] = remap[st[i].c] - 1;
            t[k].id = (short)st[i].obj->kind;
            k++;
        }
    }
    delete triOk;
    memset(remap, 0, nVerts * 4);
    for (i = 0; i < nTris; i++) {
        int a = ti[i * 16 + 10], b = ti[i * 16 + 11], c = ti[i * 16 + 12];
        int m1 = a < b ? a : b;
        int m2 = b < c ? b : c;
        if (c < a) a = c;
        remap[m1]++;
        remap[m2]++;
        remap[a]++;
    }
    int total = 0;
    int* cur = remap;
    for (i = 0; i < nVerts; i++) {
        int n = *cur;
        *cur = total;
        total += n;
        cur++;
    }
    // the prefix sums stay in `remap` (original keeps the base pointer in a separate local)
    int* table = new int[total * 3];
    memset(table, 0, total * 12);
    next = 1;
    for (i = 0; i < nTris; i++) {
        ColTriRaw* tr = (ColTriRaw*)tris + i; int* ti2 = (int*)tr;
        int a = ti2[10], b = ti2[11], c = ti2[12];
        ti2[10] = (int)((char*)wverts + a * 0x10);
        ti2[11] = (int)((char*)wverts + b * 0x10);
        ti2[12] = (int)((char*)wverts + c * 0x10);
        float* pa = &verts[a].x;
        float* pb = &verts[b].x;
        float* pc = &verts[c].x;
        ((SceneSphere*)tr)->SetTriple((ScenePoint*)pa, (ScenePoint*)pb, (ScenePoint*)pc);
        if (tr->radius == DAT_004e134c) {
            tr->id = 0x13;
            pad24 = 0;
            tr->n[0] = 0;
            ti2[7] = 0x3f800000;
            tr->n[2] = 0;
        } else {
            float u[3];
            float* up = ((V3D*)pc)->Sub(u, pa);
            DV3 w;
            float* wp = ((V3D*)pb)->Sub(w.v, pa);
            X87Cross(tr->n, wp, up);
            float kk = DAT_004e1348 / (float)sqrt(tr->n[2] * tr->n[2] + tr->n[1] * tr->n[1] + tr->n[0] * tr->n[0]);
            tr->n[0] = kk * tr->n[0];
            tr->n[1] = kk * tr->n[1];
            tr->n[2] = kk * tr->n[2];
        }
        float q = verts[a].z * tr->n[2];
        q = verts[a].y * tr->n[1] + q;
        q = verts[a].x * tr->n[0] + q;
        tr->d = q;
        centers[i].x = tr->center[0];
        centers[i].y = tr->center[1];
        centers[i].z = tr->center[2];
        int e0lo, e0hi;
        if (a < b) { e0lo = a; e0hi = b; } else { e0lo = b; e0hi = a; }
        int e1lo = b, e1hi = c;
        if (c <= b) { e1lo = c; e1hi = b; }
        int e2lo, e2hi;
        if (c < a) { e2lo = c; e2hi = a; } else { e2lo = a; e2hi = c; }
        EDGE(0, e0lo, e0hi)
        EDGE(1, e1lo, e1hi)
        EDGE(2, e2lo, e2hi)
    }
    nInts = next - 1;
    ints = new int[nInts];
    for (i = 0; i < nTris; i++) {
        ColTriRaw* q = (ColTriRaw*)tris + i;
        q->e[0] = (int)((char*)ints - 4 + q->e[0] * 4);
        q->e[1] = (int)((char*)ints - 4 + q->e[1] * 4);
        q->e[2] = (int)((char*)ints - 4 + q->e[2] * 4);
    }
    delete table;
    delete remap;
    ClearInts();
    DAT_00508504 += nVerts;
    DAT_00508508 += nTris;
    DAT_0050850c += nInts;
    ComputeSel();
}
