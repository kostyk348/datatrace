#include "ph_region.h"
#include <stdio.h>
#include <stdlib.h>

static void print_tiles(const char *label, const pr_tile_t *t)
{
    printf("%s: ", label);
    if (!t) { printf("(empty)\n"); return; }
    for (; t; t = t->next)
        printf("(%d,%d)-(%d,%d) ",
               t->rect.ul.x, t->rect.ul.y,
               t->rect.lr.x, t->rect.lr.y);
    printf("\n");
}

static int check(const char *name, int cond)
{
    printf("  %s: %s\n", name, cond ? "PASS" : "FAIL");
    return cond ? 0 : 1;
}

static int rect_subtract_visible_count(pr_rect_t a, pr_rect_t b)
{
    pr_tile_t *opaque = pr_rect_to_tile(b);
    pr_tile_t *visible = pr_calculate_visible_tiles(a, opaque);
    size_t n = pr_tile_count(visible);
    pr_free_tiles(visible);
    pr_free_tiles(opaque);
    return (int)n;
}

int main(void)
{
    int fails = 0;
    printf("=== rect_subtract: clip corner ===\n");
    {
        pr_rect_t a = { {0,0}, {100,100} };
        pr_rect_t b = { {0,0}, {50,50} };
        int n = rect_subtract_visible_count(a, b);
        print_tiles("100x100 minus 50x50 corner", NULL);
        fails += check("2 tiles", n == 2);
    }

    printf("\n=== rect_subtract: clip middle ===\n");
    {
        pr_rect_t a = { {0,0}, {100,100} };
        pr_rect_t b = { {25,25}, {75,75} };
        int n = rect_subtract_visible_count(a, b);
        print_tiles("100x100 minus 50x50 center", NULL);
        fails += check("4 tiles", n == 4);
    }

    printf("\n=== rect_subtract: clip right half ===\n");
    {
        pr_rect_t a = { {0,0}, {100,100} };
        pr_rect_t b = { {50,0}, {100,100} };
        int n = rect_subtract_visible_count(a, b);
        print_tiles("100x100 minus right half", NULL);
        fails += check("1 tile (left half)", n == 1);
    }

    printf("\n=== rect_subtract: no intersection ===\n");
    {
        pr_rect_t a = { {0,0}, {50,50} };
        pr_rect_t b = { {100,100}, {200,200} };
        int n = rect_subtract_visible_count(a, b);
        print_tiles("non-overlapping", NULL);
        fails += check("1 tile unchanged", n == 1);
    }

    printf("\n=== rect_subtract: completely covered ===\n");
    {
        pr_rect_t a = { {10,10}, {20,20} };
        pr_rect_t b = { {0,0}, {100,100} };
        int n = rect_subtract_visible_count(a, b);
        print_tiles("A inside B", NULL);
        fails += check("empty (0 tiles)", n == 0);
    }

    printf("\n=== pr_clip_tilings: two opaque windows ===\n");
    {
        pr_rect_t region = { {0,0}, {200,200} };
        pr_tile_t *w1 = pr_rect_to_tile((pr_rect_t){{10,10},{100,100}});
        pr_tile_t *w2 = pr_rect_to_tile((pr_rect_t){{50,50},{150,150}});
        w1->next = w2;

        pr_tile_t *visible = pr_calculate_visible_tiles(region, w1);
        print_tiles("200x200 behind two opaque windows", visible);

        fails += check("visible exists", visible != NULL);
        if (visible) {
            fails += check("non-zero tiles", pr_tile_count(visible) > 0);
            print_tiles("merged result", visible);
        }

        pr_free_tiles(visible);
        pr_free_tiles(w1);
    }

    printf("\n=== pr_clip_tilings: window on right edge ===\n");
    {
        pr_rect_t region = { {0,0}, {100,100} };
        pr_tile_t *opaque = pr_rect_to_tile((pr_rect_t){{50,0},{100,100}});

        pr_tile_t *visible = pr_calculate_visible_tiles(region, opaque);
        print_tiles("100x100 minus right half", visible);

        fails += check("1 tile", pr_tile_count(visible) == 1);
        pr_free_tiles(visible);
        pr_free_tiles(opaque);
    }

    printf("\n=== pr_intersect_tilings ===\n");
    {
        pr_tile_t *a = pr_rect_to_tile((pr_rect_t){{0,0},{100,100}});
        pr_tile_t *b = pr_rect_to_tile((pr_rect_t){{50,50},{150,150}});
        uint16_t n;
        pr_tile_t *inter = pr_intersect_tilings(a, b, &n);
        print_tiles("intersection of (0-100,0-100) and (50-150,50-150)", inter);
        fails += check("1 tile", n == 1);
        fails += check("expected size", inter && inter->rect.ul.x == 50 &&
                       inter->rect.ul.y == 50 &&
                       inter->rect.lr.x == 100 &&
                       inter->rect.lr.y == 100);
        pr_free_tiles(inter);
        pr_free_tiles(a);
        pr_free_tiles(b);
    }

    printf("\n=== pr_coalesce_tiles: merge adjacent ===\n");
    {
        pr_tile_t *t1 = pr_rect_to_tile((pr_rect_t){{0,0},{49,100}});
        pr_tile_t *t2 = pr_rect_to_tile((pr_rect_t){{50,0},{100,100}});
        t1->next = t2;
        print_tiles("before coalesce", t1);
        pr_tile_t *merged = pr_coalesce_tiles(t1);
        print_tiles("after coalesce", merged);
        fails += check("merged into 1 tile", pr_tile_count(merged) == 1);
        fails += check("full width", merged && merged->rect.ul.x == 0 &&
                       merged->rect.lr.x == 100);
        pr_free_tiles(merged);
    }

    printf("\n=== pr_coalesce_tiles: merge vertical ===\n");
    {
        pr_tile_t *t1 = pr_rect_to_tile((pr_rect_t){{0,0},{100,49}});
        pr_tile_t *t2 = pr_rect_to_tile((pr_rect_t){{0,50},{100,100}});
        t1->next = t2;
        print_tiles("before coalesce", t1);
        pr_tile_t *merged = pr_coalesce_tiles(t1);
        print_tiles("after coalesce", merged);
        fails += check("merged into 1 tile", pr_tile_count(merged) == 1);
        pr_free_tiles(merged);
    }

    printf("\n=== pr_clone_tiles ===\n");
    {
        pr_tile_t *orig = pr_rect_to_tile((pr_rect_t){{1,2},{3,4}});
        pr_tile_t *clone = pr_clone_tiles(orig);
        fails += check("clone matches", pr_tiles_equal(orig, clone));
        fails += check("clone is different pointer", orig != clone);
        pr_free_tiles(clone);
        pr_free_tiles(orig);
    }

    printf("\n=== Translate ===\n");
    {
        pr_tile_t *t = pr_rect_to_tile((pr_rect_t){{10,10},{20,20}});
        pr_translate_tiles(t, 5, 10);
        fails += check("translated", t->rect.ul.x == 15 && t->rect.ul.y == 20 &&
                       t->rect.lr.x == 25 && t->rect.lr.y == 30);
        pr_free_tiles(t);
    }

    printf("\n");
    if (fails)
        printf("%d TESTS FAILED\n", fails);
    else
        printf("ALL TESTS PASSED\n");
    return fails;
}
