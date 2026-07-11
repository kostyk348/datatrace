#define _POSIX_C_SOURCE 199309L
#include "ph_region.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int x, y, w, h;
    int is_opaque;
    const char *label;
} Window;

typedef struct {
    pr_tile_t *visible_tiles;
    int x, y, w, h;
    int fully_occluded;
} ViewDamage;

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void print_tiles_compact(const pr_tile_t *t, const char *label) {
    if (!t) { printf("  %s: (fully occluded)\n", label); return; }
    printf("  %s: ", label);
    int n = 0;
    for (; t; t = t->next) {
        printf("(%d,%d %dx%d)", t->rect.ul.x, t->rect.ul.y,
               t->rect.lr.x - t->rect.ul.x + 1,
               t->rect.lr.y - t->rect.ul.y + 1);
        n++;
        if (t->next) printf(", ");
    }
    printf(" (%d tiles)\n", n);
}

static int simulate_weston_repaint(Window *windows, int nw,
                                   ViewDamage *results)
{
    pr_tile_t *opaque_list = NULL;

    /*** Step 1: Build opaque tile list (windows in front-to-back order) ***/
    for (int i = nw - 1; i >= 0; i--) {
        if (!windows[i].is_opaque) continue;
        pr_tile_t *t = pr_get_tile();
        t->rect.ul.x = windows[i].x;
        t->rect.ul.y = windows[i].y;
        t->rect.lr.x = windows[i].x + windows[i].w - 1;
        t->rect.lr.y = windows[i].y + windows[i].h - 1;
        t->next = opaque_list;
        opaque_list = t;
    }

    /*** Step 2: Compute visible tiles for each window ***/
    for (int i = 0; i < nw; i++) {
        pr_rect_t r = {{windows[i].x, windows[i].y},
                      {windows[i].x + windows[i].w - 1,
                       windows[i].y + windows[i].h - 1}};

        int n_above = 0;
        for (int j = i + 1; j < nw; j++)
            if (windows[j].is_opaque) n_above++;

        if (n_above == 0) {
            results[i].visible_tiles = pr_rect_to_tile(r);
            results[i].fully_occluded = 0;
        } else {
            pr_tile_t *above = NULL;
            for (int j = i + 1; j < nw; j++) {
                if (!windows[j].is_opaque) continue;
                pr_tile_t *t = pr_get_tile();
                t->rect.ul.x = windows[j].x;
                t->rect.ul.y = windows[j].y;
                t->rect.lr.x = windows[j].x + windows[j].w - 1;
                t->rect.lr.y = windows[j].y + windows[j].h - 1;
                t->next = above;
                above = t;
            }

            /*** PHOTON: occlusion culling ***/
            results[i].visible_tiles = pr_calculate_visible_tiles(r, above);
            results[i].fully_occluded = (results[i].visible_tiles == NULL);
            pr_free_tiles(above);
        }

        results[i].x = windows[i].x;
        results[i].y = windows[i].y;
        results[i].w = windows[i].w;
        results[i].h = windows[i].h;
    }

    pr_free_tiles(opaque_list);
    return 0;
}

int main(void)
{
    printf("=== Weston-style repaint with Photon Occlusion Culling ===\n\n");

    /*** Scenario 1: Classic desktop - browser + terminal + IDE ***/
    printf("--- Scenario 1: Desktop (browser + terminal partially covered) ---\n");
    Window desktop[] = {
        {50,  50,  800, 600, 0, "Browser (back)"},
        {100, 100, 600, 400, 1, "Terminal (opaque, covers browser center)"},
        {400, 80,  300, 250, 1, "IDE (opaque, covers corner of both)"},
    };
    int n = sizeof(desktop) / sizeof(desktop[0]);
    ViewDamage results[3];

    double t0 = now_us();
    for (int iter = 0; iter < 1000; iter++) {
        for (int i = 0; i < n; i++) pr_free_tiles(results[i].visible_tiles);
        simulate_weston_repaint(desktop, n, results);
    }
    double t1 = now_us();

    for (int i = 0; i < n; i++) {
        printf("  %s at (%d,%d %dx%d):\n", desktop[i].label,
               desktop[i].x, desktop[i].y, desktop[i].w, desktop[i].h);
        print_tiles_compact(results[i].visible_tiles, "visible");
        if (results[i].fully_occluded)
            printf("    -> FULLY OCCLUDED (skip compositing!)\n");
        printf("\n");
    }
    printf("  Avg time: %.1f ns per frame\n", (t1 - t0) * 1000.0 / 1000.0);
    for (int i = 0; i < n; i++) pr_free_tiles(results[i].visible_tiles);

    /*** Scenario 2: Heavy occlusion - picture-in-picture ***/
    printf("--- Scenario 2: Cascading windows (5 overlapping) ---\n");
    Window cascade[] = {
        {0,   0,   500, 500, 0, "Window 1 (back)"},
        {50,  50,  500, 500, 0, "Window 2"},
        {100, 100, 500, 500, 0, "Window 3"},
        {150, 150, 500, 500, 1, "Window 4 (opaque)"},
        {200, 200, 500, 500, 1, "Window 5 (front, opaque)"},
    };
    n = sizeof(cascade) / sizeof(cascade[0]);
    ViewDamage results2[5];

    t0 = now_us();
    for (int iter = 0; iter < 1000; iter++) {
        for (int i = 0; i < n; i++) pr_free_tiles(results2[i].visible_tiles);
        simulate_weston_repaint(cascade, n, results2);
    }
    t1 = now_us();

    for (int i = 0; i < n; i++) {
        print_tiles_compact(results2[i].visible_tiles, cascade[i].label);
        if (results2[i].fully_occluded)
            printf("    -> FULLY OCCLUDED\n");
    }
    printf("  Avg time: %.1f ns per frame\n", (t1 - t0) * 1000.0 / 1000.0);
    for (int i = 0; i < n; i++) pr_free_tiles(results2[i].visible_tiles);

    /*** Scenario 3: Full desktop stress test (50 random windows) ***/
    printf("\n--- Scenario 3: 50 random windows (stress test) ---\n");
    srand(42);
    #define N50 50
    Window stress[N50];
    for (int i = 0; i < N50; i++) {
        stress[i].w = rand() % 400 + 100;
        stress[i].h = rand() % 400 + 100;
        stress[i].x = rand() % (1920 - stress[i].w);
        stress[i].y = rand() % (1080 - stress[i].h);
        stress[i].is_opaque = (rand() % 3 != 0);  // 66% opaque
    }
    ViewDamage results3[N50];

    t0 = now_us();
    int total_frames = 100;
    for (int iter = 0; iter < total_frames; iter++) {
        for (int i = 0; i < N50; i++) pr_free_tiles(results3[i].visible_tiles);
        simulate_weston_repaint(stress, N50, results3);
    }
    t1 = now_us();

    int occluded = 0, visible_total = 0;
    for (int i = 0; i < N50; i++) {
        if (results3[i].fully_occluded) occluded++;
        else visible_total += pr_tile_count(results3[i].visible_tiles);
    }
    printf("  Windows: %d, Opaque: ~%d, Fully occluded: %d\n",
           N50, N50 * 2 / 3, occluded);
    printf("  Total visible tiles across all windows: %d\n", visible_total);
    printf("  Avg time: %.1f us per frame\n", (t1 - t0) / total_frames);

    for (int i = 0; i < N50; i++) pr_free_tiles(results3[i].visible_tiles);

    printf("\n=== Key insight for Wayland compositors ===\n");
    printf("  Photon-style occlusion culling can:\n");
    printf("  - Skip compositing fully occluded views (%.0f%% in stress test)\n",
           (double)occluded / N50 * 100);
    printf("  - Provide exact visible tile list for partial repaint\n");
    printf("  - Integration point: weston_view_damage_below() in compositor.c\n");

    return 0;
}
