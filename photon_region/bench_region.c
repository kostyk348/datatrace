#define _POSIX_C_SOURCE 199309L
#include "ph_region.h"
#include <pixman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int rand_int(int min, int max) {
    return min + rand() % (max - min + 1);
}

static int cmp_u64(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

// Run N iterations, return median time in us
static double bench_n( void (*fn)(void *), void *ctx, int N ) {
    double *samples = calloc(N, sizeof(double));
    for (int i = 0; i < N; i++) {
        double t0 = now_us();
        fn(ctx);
        double t1 = now_us();
        samples[i] = t1 - t0;
    }
    qsort(samples, N, sizeof(double), cmp_u64);
    double med = samples[N / 2];
    free(samples);
    return med;
}

static int count_ph(const pr_tile_t *t) {
    int n = 0;
    for (; t; t = t->next) n++;
    return n;
}

static void pr_make_random_tiles(pr_tile_t **out, pixman_region32_t *px,
                                  int n, int W, int H) {
    *out = NULL;
    for (int j = 0; j < n; j++) {
        int w = rand_int(50, 400);
        int h = rand_int(50, 400);
        int x = rand_int(0, W - w);
        int y = rand_int(0, H - h);
        pr_tile_t *t = pr_get_tile();
        t->rect.ul.x = x; t->rect.ul.y = y;
        t->rect.lr.x = x + w - 1; t->rect.lr.y = y + h - 1;
        t->next = *out;
        *out = t;
        pixman_region32_union_rect(px, px, x, y, w, h);
    }
}

struct ctx_sub { pr_tile_t *a; const pr_tile_t *b; pr_tile_t *r; pixman_region32_t pa, pb, pr; };
static void run_sub_ph(void *p) {
    struct ctx_sub *c = p;
    pr_free_tiles(c->r);
    c->r = pr_subtract_tilings(pr_clone_tiles(c->a), c->b);
}
static void run_sub_px(void *p) {
    struct ctx_sub *c = p;
    pixman_region32_fini(&c->pr);
    pixman_region32_init(&c->pr);
    pixman_region32_subtract(&c->pr, &c->pa, &c->pb);
}

struct ctx_int { pr_tile_t *a, *b, *r; pixman_region32_t pa, pb, pr; };
static void run_int_ph(void *p) {
    struct ctx_int *c = p;
    pr_free_tiles(c->r);
    c->r = pr_intersect_tilings(c->a, c->b, NULL);
}
static void run_int_px(void *p) {
    struct ctx_int *c = p;
    pixman_region32_fini(&c->pr);
    pixman_region32_init(&c->pr);
    pixman_region32_intersect(&c->pr, &c->pa, &c->pb);
}

struct ctx_uni { pr_tile_t *a, *b, *r; pixman_region32_t pa, pb, pr; };
static void run_uni_ph(void *p) {
    struct ctx_uni *c = p;
    pr_free_tiles(c->r);
    c->r = pr_clone_tiles(c->a);
    c->r = pr_merge_tiles(c->r, c->b);
    c->r = pr_coalesce_tiles(c->r);
}
static void run_uni_px(void *p) {
    struct ctx_uni *c = p;
    pixman_region32_fini(&c->pr);
    pixman_region32_init(&c->pr);
    pixman_region32_union(&c->pr, &c->pa, &c->pb);
}

static void bench(const char *label, int ph_rects, int px_rects,
                  double ph_us, double px_us) {
    double ratio = (px_us > 0.001) ? px_us / (ph_us > 0.001 ? ph_us : 0.001) : 0;
    const char *winner = ph_us < px_us ? "pr" : "px";
    printf("  %-36s | pr: %7.2f us | px: %7.2f us | %s x%.2f | tiles pr=%d px=%d\n",
           label, ph_us, px_us, winner, ratio, ph_rects, px_rects);
}

static void do_bench_subtract(int iterations, int nwin, int W, int H) {
    srand(42);
    double ph_sum = 0, px_sum = 0;
    int ph_r = 0, px_r = 0;

    for (int i = 0; i < iterations; i++) {
        struct ctx_sub c = {0};
        pixman_region32_init(&c.pa);
        pixman_region32_init(&c.pb);
        pixman_region32_init(&c.pr);
        pr_make_random_tiles(&c.a, &c.pa, nwin, W, H);
        pr_make_random_tiles((pr_tile_t **)&c.b, &c.pb, nwin / 2 + 1, W, H);

        double t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pr_free_tiles(c.r);
            c.r = pr_subtract_tilings(pr_clone_tiles(c.a), c.b);
        }
        ph_sum += (now_us() - t0) / 10;
        ph_r = count_ph(c.r);

        t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pixman_region32_fini(&c.pr);
            pixman_region32_init(&c.pr);
            pixman_region32_subtract(&c.pr, &c.pa, &c.pb);
        }
        px_sum += (now_us() - t0) / 10;
        int nb = 0;
        pixman_region32_rectangles(&c.pr, &nb);
        px_r = nb;

        pr_free_tiles(c.a);
        pr_free_tiles((pr_tile_t *)c.b);
        pr_free_tiles(c.r);
        pixman_region32_fini(&c.pa);
        pixman_region32_fini(&c.pb);
        pixman_region32_fini(&c.pr);
    }

    char label[64];
    snprintf(label, sizeof(label), "subtract [%d rects * %d clips]", nwin, nwin / 2 + 1);
    bench(label, ph_r, px_r, ph_sum / iterations, px_sum / iterations);
}

static void do_bench_intersect(int iterations, int nwin, int W, int H) {
    srand(42);
    double ph_sum = 0, px_sum = 0;
    int ph_r = 0, px_r = 0;

    for (int i = 0; i < iterations; i++) {
        struct ctx_int c = {0};
        pixman_region32_init(&c.pa);
        pixman_region32_init(&c.pb);
        pixman_region32_init(&c.pr);
        pr_make_random_tiles(&c.a, &c.pa, nwin, W, H);
        pr_make_random_tiles(&c.b, &c.pb, nwin, W, H);

        double t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pr_free_tiles(c.r);
            c.r = pr_intersect_tilings(c.a, c.b, NULL);
        }
        ph_sum += (now_us() - t0) / 10;
        ph_r = count_ph(c.r);

        t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pixman_region32_fini(&c.pr);
            pixman_region32_init(&c.pr);
            pixman_region32_intersect(&c.pr, &c.pa, &c.pb);
        }
        px_sum += (now_us() - t0) / 10;
        int nb = 0;
        pixman_region32_rectangles(&c.pr, &nb);
        px_r = nb;

        pr_free_tiles(c.a);
        pr_free_tiles(c.b);
        pr_free_tiles(c.r);
        pixman_region32_fini(&c.pa);
        pixman_region32_fini(&c.pb);
        pixman_region32_fini(&c.pr);
    }

    char label[64];
    snprintf(label, sizeof(label), "intersect [%d rects]", nwin);
    bench(label, ph_r, px_r, ph_sum / iterations, px_sum / iterations);
}

static void do_bench_union(int iterations, int nwin, int W, int H) {
    srand(42);
    double ph_sum = 0, px_sum = 0;
    int ph_r = 0, px_r = 0;

    for (int i = 0; i < iterations; i++) {
        struct ctx_uni c = {0};
        pixman_region32_init(&c.pa);
        pixman_region32_init(&c.pb);
        pixman_region32_init(&c.pr);
        pr_make_random_tiles(&c.a, &c.pa, nwin, W, H);
        pr_make_random_tiles(&c.b, &c.pb, nwin, W, H);

        double t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pr_free_tiles(c.r);
            c.r = pr_clone_tiles(c.a);
            c.r = pr_merge_tiles(c.r, c.b);
            c.r = pr_coalesce_tiles(c.r);
        }
        ph_sum += (now_us() - t0) / 10;
        ph_r = count_ph(c.r);

        t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pixman_region32_fini(&c.pr);
            pixman_region32_init(&c.pr);
            pixman_region32_union(&c.pr, &c.pa, &c.pb);
        }
        px_sum += (now_us() - t0) / 10;
        int nb = 0;
        pixman_region32_rectangles(&c.pr, &nb);
        px_r = nb;

        pr_free_tiles(c.a);
        pr_free_tiles(c.b);
        pr_free_tiles(c.r);
        pixman_region32_fini(&c.pa);
        pixman_region32_fini(&c.pb);
        pixman_region32_fini(&c.pr);
    }

    char label[64];
    snprintf(label, sizeof(label), "union+coalesce [%d rects]", nwin);
    bench(label, ph_r, px_r, ph_sum / iterations, px_sum / iterations);
}

static void do_bench_occlusion(int iterations, int nlayers, int nopaque, int W, int H) {
    srand(42);
    double ph_sum = 0, px_sum = 0;

    for (int i = 0; i < iterations; i++) {
        pr_rect_t region = {{0, 0}, {W - 1, H - 1}};

        pr_tile_t *opaque_ph = NULL;
        pixman_region32_t opaque_px;
        pixman_region32_init(&opaque_px);

        // nlayers: concentric shrinking rects (fully opaque)
        for (int j = 0; j < nlayers; j++) {
            int s = j * 30;
            int w = W - 2 * s, h = H - 2 * s;
            if (w < 10) w = 10;
            if (h < 10) h = 10;
            pr_tile_t *t = pr_get_tile();
            t->rect.ul.x = s; t->rect.ul.y = s;
            t->rect.lr.x = s + w - 1; t->rect.lr.y = s + h - 1;
            t->next = opaque_ph;
            opaque_ph = t;
            pixman_region32_union_rect(&opaque_px, &opaque_px, s, s, w, h);
        }

        // nopaque: random non-opaque windows (just for pixman path)
        // (not used in Photon path since PhClipTilings takes const)
        // We measure pixman doing subtract of the whole opaque region
        // vs Photon subtracting each opaque rect.

        double t0 = now_us();
        pr_tile_t *vis = NULL;
        for (int r = 0; r < 10; r++) {
            pr_free_tiles(vis);
            vis = pr_calculate_visible_tiles(region, opaque_ph);
        }
        ph_sum += (now_us() - t0) / 10;

        pixman_region32_t rgn;
        pixman_region32_init_rect(&rgn, 0, 0, W, H);
        pixman_region32_t r2;
        pixman_region32_init(&r2);
        t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pixman_region32_fini(&r2);
            pixman_region32_init(&r2);
            pixman_region32_subtract(&r2, &rgn, &opaque_px);
        }
        px_sum += (now_us() - t0) / 10;

        pr_free_tiles(vis);
        pr_free_tiles(opaque_ph);
        pixman_region32_fini(&rgn);
        pixman_region32_fini(&r2);
        pixman_region32_fini(&opaque_px);
    }

    char label[64];
    snprintf(label, sizeof(label), "occlusion [%d layers]", nlayers);
    bench(label, 0, 0, ph_sum / iterations, px_sum / iterations);
}

// Simulate wlroots scene_node_update_iterator() cycle:
// For each window (in z-order):
//   1. visible = (old - update_region) ∪ (accum \xe2\x88\xa9 bounds)
//   2. accum -= opaque
static void do_bench_scene_cycle(int iterations, int nwin, int W, int H,
                                 const char *label) {
    srand(42);

    // Pre-generate window positions
    int *wx = malloc(nwin * sizeof(int));
    int *wy = malloc(nwin * sizeof(int));
    int *ww = malloc(nwin * sizeof(int));
    int *wh = malloc(nwin * sizeof(int));
    for (int i = 0; i < nwin; i++) {
        ww[i] = rand_int(200, 600);
        wh[i] = rand_int(200, 500);
        wx[i] = rand_int(0, W - ww[i]);
        wy[i] = rand_int(0, H - wh[i]);
    }

    // Update region: small dirty rect
    pr_rect_t update_rect = {{50, 50}, {150, 150}};
    pixman_region32_t update_px;
    pixman_region32_init_rect(&update_px, 50, 50, 100, 100);

    double ph_sum = 0, px_sum = 0;

    for (int it = 0; it < iterations; it++) {
        // --- pr_region path ---
        pr_tile_t *accum = NULL;
        double t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pr_free_tiles(accum);
            accum = NULL;

            // Process windows in z-order
            for (int i = 0; i < nwin; i++) {
                // node bounds
                pr_rect_t bounds = {{(int16_t)wx[i], (int16_t)wy[i]},
                                    {(int16_t)(wx[i] + ww[i] - 1),
                                     (int16_t)(wy[i] + wh[i] - 1)}};

                // visible starts as bounds
                pr_tile_t *visible = pr_rect_to_tile(bounds);

                // subtract update_region from visible
                visible = pr_subtract_rect(visible, update_rect);

                // intersect accum with bounds => new_part
                pr_tile_t *new_part = NULL;
                if (accum) {
                    new_part = pr_intersect_rect(accum, bounds, NULL);
                }

                // union (persist) with new_part
                if (new_part) {
                    visible = pr_merge_tiles(visible, new_part);
                    visible = pr_coalesce_tiles(visible);
                    pr_free_tiles(new_part);
                }

                // accum -= opaque (opaque = bounds for solid windows)
                if (accum) {
                    accum = pr_subtract_rect(accum, bounds);
                } else {
                    pr_tile_t *opq = pr_rect_to_tile(bounds);
                    accum = pr_clone_tiles(opq);
                    pr_free_tiles(opq);
                }

                pr_free_tiles(visible);
            }
        }
        ph_sum += (now_us() - t0) / 10;

        // --- pixman path ---
        pixman_region32_t accum_px;
        pixman_region32_init(&accum_px);
        t0 = now_us();
        for (int r = 0; r < 10; r++) {
            pixman_region32_fini(&accum_px);
            pixman_region32_init(&accum_px);

            for (int i = 0; i < nwin; i++) {
                pixman_region32_t visible;
                pixman_region32_init_rect(&visible, wx[i], wy[i], ww[i], wh[i]);

                pixman_region32_subtract(&visible, &visible, &update_px);
                pixman_region32_intersect_rect(&visible, &visible,
                                               wx[i], wy[i], ww[i], wh[i]);

                pixman_region32_t tmp;
                pixman_region32_init(&tmp);
                pixman_region32_intersect(&tmp, &accum_px, &visible);
                pixman_region32_union(&visible, &visible, &tmp);
                pixman_region32_fini(&tmp);

                pixman_region32_t opaque;
                pixman_region32_init_rect(&opaque, wx[i], wy[i], ww[i], wh[i]);
                pixman_region32_subtract(&accum_px, &accum_px, &opaque);
                pixman_region32_fini(&opaque);
                pixman_region32_fini(&visible);
            }
        }
        px_sum += (now_us() - t0) / 10;
        pixman_region32_fini(&accum_px);
    }

    free(wx); free(wy); free(ww); free(wh);
    bench(label, 0, 0, ph_sum / iterations, px_sum / iterations);
}

int main(void) {
    printf("pr_region vs pixman benchmark\n");
    printf("pixman: %s\n", PIXMAN_VERSION_STRING);
    printf("========================================\n");

    int iters = 500;

    printf("\n--- Light scenes (2-10 rects, typical desktop) ---\n");
    do_bench_subtract(iters, 5, 1920, 1080);
    do_bench_intersect(iters, 5, 1920, 1080);
    do_bench_union(iters, 5, 1920, 1080);

    printf("\n--- Heavy scenes (50-200 rects, complex overlap) ---\n");
    do_bench_subtract(iters, 50, 1920, 1080);
    do_bench_intersect(iters, 50, 1920, 1080);
    do_bench_union(iters, 50, 1920, 1080);

    printf("\n--- Realistic wlroots scene cycle ---\n");
    do_bench_scene_cycle(iters, 5, 1920, 1080, "cycle [5 windows, small update]");
    do_bench_scene_cycle(iters, 10, 1920, 1080, "cycle [10 windows, small update]");
    do_bench_scene_cycle(iters, 20, 1920, 1080, "cycle [20 windows, small update]");

    printf("\n--- Occlusion culling ---\n");
    do_bench_occlusion(iters, 5, 0, 1920, 1080);
    do_bench_occlusion(iters, 20, 0, 1920, 1080);

    printf("\nDone.\n");
    return 0;
}
