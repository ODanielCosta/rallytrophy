// Car::SunFactor (0x45dac0-0x45de8f, stub 0x45de60). Map: analysis/range-459890.md section 3.
#include "unk_481390.h"
#include "unk_4843e0.h"
#include "rallytrophy.h"
#include "unk_45dac0.h"

// The Car as SunFactor sees it: the body at +0x24 (second matrix at +0x60, reference point at +0xb8).
struct SunCar {
    BYTE unk0[0x24];
    BYTE* body;                        // 0x24
};

bool PointInTriangle(const Vec3* point, const SunTri* tri, const SunVertex* a, const SunVertex* b,
                     const SunVertex* c); // 0x4b3ee0
void BarycentricWeights(const SunVertex* a, const SunVertex* b, const SunVertex* c, const Vec3* point,
                        Vec3* weights); // 0x4b3470

// Transforms *point by *matrix (row vectors, translation at +0x30) into *result.
#define SUN_TRANSFORM() \
    __asm mov ecx, point \
    __asm mov edx, matrix \
    __asm mov eax, result \
    __asm fld dword ptr [ecx] \
    __asm fmul dword ptr [edx] \
    __asm fld dword ptr [ecx] \
    __asm fmul dword ptr [edx+4] \
    __asm fld dword ptr [ecx] \
    __asm fmul dword ptr [edx+8] \
    __asm fld dword ptr [ecx+4] \
    __asm fmul dword ptr [edx+16] \
    __asm fld dword ptr [ecx+4] \
    __asm fmul dword ptr [edx+20] \
    __asm fld dword ptr [ecx+4] \
    __asm fmul dword ptr [edx+24] \
    __asm fxch st(2) \
    __asm faddp st(5), st \
    __asm faddp st(3), st \
    __asm faddp st(1), st \
    __asm fld dword ptr [ecx+8] \
    __asm fmul dword ptr [edx+32] \
    __asm fld dword ptr [ecx+8] \
    __asm fmul dword ptr [edx+36] \
    __asm fld dword ptr [ecx+8] \
    __asm fmul dword ptr [edx+40] \
    __asm fxch st(2) \
    __asm faddp st(5), st \
    __asm faddp st(3), st \
    __asm faddp st(1), st \
    __asm fxch st(2) \
    __asm fadd dword ptr [edx+48] \
    __asm fxch st(1) \
    __asm fadd dword ptr [edx+52] \
    __asm fxch st(2) \
    __asm fadd dword ptr [edx+56] \
    __asm fxch st(1) \
    __asm fstp dword ptr [eax] \
    __asm fstp dword ptr [eax+8] \
    __asm fstp dword ptr [eax+4]

struct SunMeshV { BYTE unk0[0x30]; std::vector<SunPart*> parts; };
// 2026-11-23: this body is the hill-climbing permuter's best for the range
// (tools/permute.py -r 40 -n 24 -s 7): hoisted `verts`/`dx` declarations, pre-increment
// loop counters, commuted pointer additions, (int) copies for `cand`/`best`, and the
// hit-store order best/hitA/hitTri/hit/hitB/hitC/hits. 108 -> 98 differing bytes (58 ->
// 53 instructions); the function stays 921 bytes and the semantics are unchanged from
// the previous body (same tests, same stores, same call arguments).
// Residual 98 bytes are all codegen choice, in five fixed clusters: (1) the outer
// `parts[i]` load is held in edx and re-loaded in edx (built: eax), (2) the WORD count
// temporary is eax with no [ebp-0x20] store (built: edx plus the store), (3) the
// triangle-record cursor is edx and is never spilled to [ebp-0x1c]/[ebp-0x20] (built:
// ebx plus both stores), (4) the three plane dot-product first terms load from
// [ebp-0x58]/[ebp-0x54]/[ebp-0x50] (built: [ebx-0x10]/[ebx-0xc]/[ebx-0x14]), (5) the
// post-`continue` block uses eax/edi/edx/ebx instead of built ebx/esi/esi/ecx with
// [ebp-0x60] (built [ebp-0x68]) and [ebp-0x70] (built [ebp-0x14]) homes. From there the
// fmul/fadd ladder and the three fstp stores re-align byte-for-byte; only the loop
// tail (add edx,0x20; spill edx/eax to [ebp-0x1c]/[ebp-0x20]) and the epilogue stack
// argument homes remain. About 100 further hand probes of homes, registers, argument
// shapes and float temporaries did not reduce the count.
// NONMATCHING: RALLYTROPHY 0x45dac0
// One advancing triangle-record cursor for plane fields and nx, alongside the separately advancing tri pointer,
// cuts the differing-byte count from 468 to 403. A volatile WORD read assigned to int preserves the target's later
// count-load order and 32-bit decrement (422→403). The earlier 422-difference cursor-only variant was invalid
// because it passed a stale triangle pointer; this version keeps tri++.
// The sequential h assignments follow the target's x87 term order. Cursor/index registers, local homes, and
// vertex-index call setup still differ from the target.
// Tried 2026-10-30 night: nx via tri->nx and ny via tri->ny (not q[]) plus part/verts/tri/count load order took 101->52 insns; ~20 variants (all-tri fields, unsigned/nonvolatile count, decl order) no better; still differs in count/idx spill order and tri/cursor registers.
// Tried 2026-10-31: ny via q[-5] (original reads [edx-0x14]) and parts[i] re-read per field (original loads it twice) 52->50; ~25 more variants (field load order, nx via q[-6] wrong, split h terms, cand store order, unsigned/WORD count) no better; ~50 insns apart, permuter skipped.
// 2026-11-11: 514 -> 106 bytes, size now exact (921). mesh->parts is a std::vector (SunMeshV view): its operator[]
// gives the original's two consecutive loads of parts[i]; count as a plain int (no volatile WORD read); statement
// order count, vertices, indices, tri. Left (44 insns): the original keeps i in ebx through the inner loop and the
// record cursor in edx, here the cursor takes ebx. No gain: const/non-const operator[], rec[k]/idx[k*3] indexing
// (125 insns), all fields through tri (907 bytes), h forms, count types, declaration placement.
// 2026-11-16 (round 21): cand stored z, x, then y (y computed first) 44 -> 43 insns, 106 -> 105 bytes. No gain: ny via q[-5]
// (66 insns), cursor recomputed per iteration, q/tri/idx increment order, unsigned short/for(;;)/--n>0 count, eps hoisted,
// signed i, hit field-wise, cand = p.
float Car::SunFactor(void* models)
{
    SunModels* list = (SunModels*)models;
    Vec3 p;
    {
        BYTE* body = ((SunCar*)this)->body;
        const float* matrix;
        const float* point;
        float* result;
        matrix = (const float*)(body + 0x60);
        point = (const float*)(0xb8 + body);
        result = (float*)&p;
        SUN_TRANSFORM();
    }
    const SunTri* hitTri = 0;
    const SunVertex* hitA = 0;
    Vec3 hit;
    float best = 999999.0f;
    int hits = 0;
    const SunVertex* hitB;
    const SunVertex* hitC;
    for (int m = 0; m < list->count; ++m) {
        SunModel* model = list->models[m];
        if (model->kind != 1 || !(model->flags & 4) || !(model->flagsCc & 1)) {
            continue;
        }
        std::vector<SunTri*>* tris = model->meshes.tris;
        SunMesh* mesh = model->meshes.At(0);
        if (!tris) {
            continue;
        }
        float dx;
        dx = p.x - model->centreX;
        float dz = p.z - model->centreZ;
        float dist = dx * dx + dz * dz;
        float r = model->radius;
        float r2 = r * r;
        if (*(int*)&dist > *(int*)&r2) {
            continue;
        }
        for (unsigned i = 0; i < tris->size(); ++i) {
            SunVertex* verts;
            int n = ((SunMeshV*)mesh)->parts[i]->count;
            verts = ((SunMeshV*)mesh)->parts[i]->vertices;
            const unsigned short* idx = ((SunMeshV*)mesh)->parts[i]->indices;
            SunTri* tri = (*tris)[i];
            if (!n) {
                continue;
            }
            float eps = 0.00001f;
            const float* q = &tri->cz;
            do {
                if (*(int*)&q[-5] >= *(int*)&eps) {
                    float r = q[1];
                    if (!(q[-1] - p.y > r)) {
                        float tx = p.x - q[-2];
                        float tz = p.z - q[0];
                        if (!(tx * tx + tz * tz > r * r)) {
                            float h = p.z * q[-4] + p.y * tri->ny;
                            h = h + p.x * tri->nx;
                            h = h - q[-3];
                            if (!(*(unsigned*)&h & 0x80000000)) {
                                float t = h / q[-5];
                                if (!(t > best)) {
                                    Vec3 cand;
                                    cand.z = p.z;
                                    float cy = p.y - t;
                                    int cp35805__ = *(int*)&(p.x);
                                    *(int*)&(cand.x) = cp35805__;
                                    cand.y = cy;
                                    const SunVertex* c = &verts[idx[2]];
                                    const SunVertex* b = &verts[idx[1]];
                                    const SunVertex* a = &verts[idx[0]];
                                    if (PointInTriangle(&cand, tri, a, b, c)) {
                                        *(int*)&(best) = (*(int*)&(t));
                                        hitA = a;
                                        hitTri = tri;
                                        hit = cand;
                                        hitB = b;
                                        hitC = c;
                                        hits++;
                                    }
                                }
                            }
                        }
                    }
                }
                q = (8) + q;
                ++tri;
                idx = (3) + idx;
            } while (--n);
        }
    }
    if (hitTri) {
        Vec3 w;
        BarycentricWeights(hitA, hitB, hitC, &hit, &w);
        return (hitA->shade * w.x + hitB->shade * w.y + hitC->shade * w.z) * (1.0f / 255.0f);
    }
    return 1.0f;
}

// Module end: guard-bit initialiser of the STL header statics and its atexit registration.

// FUNCTION: RALLYTROPHY 0x45de60
// SYMBOL: _$E23
typedef void Generated_45de60();

// FUNCTION: RALLYTROPHY 0x45de80
// SYMBOL: _$E22
typedef void Generated_45de80();
