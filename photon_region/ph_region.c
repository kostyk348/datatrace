#include "ph_region.h"
#include <stdlib.h>
#include <string.h>

static int rect_intersects(pr_rect_t a, pr_rect_t b)
{
    int dx1 = (int)a.lr.x - (int)b.ul.x;
    int dx2 = (int)b.lr.x - (int)a.ul.x;
    int dy1 = (int)a.lr.y - (int)b.ul.y;
    int dy2 = (int)b.lr.y - (int)a.ul.y;
    return ((dx1 | dx2 | dy1 | dy2) >> 31) == 0;
}

static pr_rect_t rect_intersection(pr_rect_t a, pr_rect_t b)
{
    pr_rect_t r;
    r.ul.x = (a.ul.x > b.ul.x) ? a.ul.x : b.ul.x;
    r.ul.y = (a.ul.y > b.ul.y) ? a.ul.y : b.ul.y;
    r.lr.x = (a.lr.x < b.lr.x) ? a.lr.x : b.lr.x;
    r.lr.y = (a.lr.y < b.lr.y) ? a.lr.y : b.lr.y;
    return r;
}

static int rect_contains(pr_rect_t outer, pr_rect_t inner)
{
    int d1 = (int)inner.ul.x - (int)outer.ul.x;
    int d2 = (int)inner.ul.y - (int)outer.ul.y;
    int d3 = (int)outer.lr.x - (int)inner.lr.x;
    int d4 = (int)outer.lr.y - (int)inner.lr.y;
    return ((d1 | d2 | d3 | d4) >> 31) == 0;
}

static int rect_equal(pr_rect_t a, pr_rect_t b)
{
    int d1 = (int)a.ul.x ^ (int)b.ul.x;
    int d2 = (int)a.ul.y ^ (int)b.ul.y;
    int d3 = (int)a.lr.x ^ (int)b.lr.x;
    int d4 = (int)a.lr.y ^ (int)b.lr.y;
    return (d1 | d2 | d3 | d4) == 0;
}

static int rect_valid(pr_rect_t r)
{
    int dx = (int)r.lr.x - (int)r.ul.x;
    int dy = (int)r.lr.y - (int)r.ul.y;
    return ((dx | dy) >> 31) == 0;
}

pr_rect_t pr_rect_intersection(pr_rect_t a, pr_rect_t b)
{
    return rect_intersection(a, b);
}

int pr_rect_intersects(pr_rect_t a, pr_rect_t b)
{
    return rect_intersects(a, b);
}

int pr_rect_contains(pr_rect_t a, pr_rect_t b)
{
    return rect_contains(a, b);
}

static __thread pr_tile_t *tile_freelist;

pr_tile_t *pr_get_tile(void)
{
    pr_tile_t *t = tile_freelist;
    if (t) {
        tile_freelist = t->next;
    } else {
        t = (pr_tile_t *)malloc(sizeof(pr_tile_t));
        if (!t) return NULL;
    }
    t->rect.ul.x = 0; t->rect.ul.y = 0; t->rect.lr.x = -1; t->rect.lr.y = -1;
    t->next = NULL;
    return t;
}

void pr_free_tiles(pr_tile_t *tiles)
{
    if (!tiles) return;
    pr_tile_t *last = tiles;
    while (last->next) last = last->next;
    last->next = tile_freelist;
    tile_freelist = tiles;
}

pr_tile_t *pr_clone_tiles(const pr_tile_t *tiles)
{
    pr_tile_t head, *tail = &head;
    head.next = NULL;
    for (; tiles; tiles = tiles->next) {
        pr_tile_t *t = pr_get_tile();
        if (!t) { pr_free_tiles(head.next); return NULL; }
        t->rect = tiles->rect;
        tail->next = t;
        tail = t;
    }
    return head.next;
}

pr_tile_t *pr_rect_to_tile(pr_rect_t r)
{
    if (!rect_valid(r)) return NULL;
    pr_tile_t *t = pr_get_tile();
    if (!t) return NULL;
    t->rect = r;
    return t;
}

static pr_tile_t *tile_prepend(pr_tile_t **list, pr_rect_t r)
{
    if (!rect_valid(r)) return NULL;
    pr_tile_t *t = pr_get_tile();
    if (!t) return NULL;
    t->rect = r;
    t->next = *list;
    *list = t;
    return t;
}

static void subtract_one(pr_rect_t a, pr_rect_t b, pr_tile_t **out)
{
    if (!rect_intersects(a, b)) {
        tile_prepend(out, a);
        return;
    }
    if (rect_contains(b, a)) {
        return;
    }

    if (b.ul.y > a.ul.y) {
        tile_prepend(out, ((pr_rect_t){{a.ul.x, a.ul.y}, {a.lr.x, (int16_t)(b.ul.y - 1)}}));
    }
    if (b.lr.y < a.lr.y) {
        tile_prepend(out, ((pr_rect_t){{a.ul.x, (int16_t)(b.lr.y + 1)}, {a.lr.x, a.lr.y}}));
    }

    int top_clip_y = (b.ul.y > a.ul.y) ? b.ul.y : a.ul.y;
    int bot_clip_y = (b.lr.y < a.lr.y) ? b.lr.y : a.lr.y;

    if (top_clip_y <= bot_clip_y) {
        if (b.ul.x > a.ul.x) {
            tile_prepend(out, ((pr_rect_t){{a.ul.x, (int16_t)top_clip_y},
                                         {(int16_t)(b.ul.x - 1), (int16_t)bot_clip_y}}));
        }
        if (b.lr.x < a.lr.x) {
            tile_prepend(out, ((pr_rect_t){{(int16_t)(b.lr.x + 1), (int16_t)top_clip_y},
                                         {a.lr.x, (int16_t)bot_clip_y}}));
        }
    }
}

// In-place subtract: non-intersecting tiles relinked to result (zero alloc),
// fully covered tiles freed, partial overlaps split via subtract_one.
static pr_tile_t *subtract_list_inplace(pr_tile_t *tiles, pr_rect_t clip_rect)
{
    pr_tile_t *result = NULL;

    for (pr_tile_t *t = tiles; t; ) {
        pr_tile_t *next = t->next;
        t->next = result;

        if (!rect_intersects(t->rect, clip_rect)) {
            result = t;
        } else if (rect_contains(clip_rect, t->rect)) {
            t->next = NULL; pr_free_tiles(t);
        } else {
            t->next = NULL;
            subtract_one(t->rect, clip_rect, &result);
            pr_free_tiles(t);
        }

        t = next;
    }

    return result;
}

// Clip (subtract) one rect, optionally returning intersection.
static pr_tile_t *clip_list_from_rect(pr_tile_t *tiles, pr_rect_t clip_rect,
                                     pr_tile_t **intersection)
{
    if (!intersection) {
        return subtract_list_inplace(tiles, clip_rect);
    }

    pr_tile_t *result = NULL;
    pr_tile_t *inter = NULL;

    for (pr_tile_t *t = tiles; t; t = t->next) {
        pr_rect_t inter_rect = rect_intersection(t->rect, clip_rect);
        if (rect_valid(inter_rect)) {
            tile_prepend(&inter, inter_rect);
        }
        subtract_one(t->rect, clip_rect, &result);
    }

    *intersection = inter;
    pr_free_tiles(tiles);
    return result;
}

pr_tile_t *pr_clip_tilings(pr_tile_t *tiles,
                            const pr_tile_t *clip_tiles,
                            pr_tile_t **intersection)
{
    if (!tiles) return NULL;

    if (!intersection) {
        for (; clip_tiles; clip_tiles = clip_tiles->next) {
            tiles = subtract_list_inplace(tiles, clip_tiles->rect);
            if (!tiles) return NULL;
        }
        return tiles;
    }

    pr_tile_t *inter_acc = NULL;

    for (; clip_tiles; clip_tiles = clip_tiles->next) {
        pr_tile_t *clip_inter = NULL;
        tiles = clip_list_from_rect(tiles, clip_tiles->rect, &clip_inter);

        if (clip_inter) {
            if (!inter_acc) {
                inter_acc = clip_inter;
            } else {
                pr_tile_t *last = inter_acc;
                while (last->next) last = last->next;
                last->next = clip_inter;
            }
        }
    }

    *intersection = inter_acc;
    return tiles;
}

pr_tile_t *pr_subtract_tilings(pr_tile_t *tiles,
                                const pr_tile_t *clip_tiles)
{
    return pr_clip_tilings(tiles, clip_tiles, NULL);
}

pr_tile_t *pr_subtract_rect(pr_tile_t *tiles, pr_rect_t clip_rect)
{
    if (!tiles) return NULL;
    return subtract_list_inplace(tiles, clip_rect);
}

pr_tile_t *pr_intersect_tilings(const pr_tile_t *a,
                                 const pr_tile_t *b,
                                 uint16_t *count)
{
    if (!a || !b) { if (count) *count = 0; return NULL; }

    pr_tile_t *result = NULL;
    uint16_t n = 0;

    for (; a; a = a->next) {
        for (const pr_tile_t *bb = b; bb; bb = bb->next) {
            pr_rect_t inter = rect_intersection(a->rect, bb->rect);
            if (rect_valid(inter)) {
                tile_prepend(&result, inter);
                n++;
            }
        }
    }

    if (count) *count = n;
    return result;
}

pr_tile_t *pr_intersect_rect(const pr_tile_t *tiles, pr_rect_t r,
                              uint16_t *count)
{
    if (!tiles || !rect_valid(r)) { if (count) *count = 0; return NULL; }

    pr_tile_t *result = NULL;
    uint16_t n = 0;

    for (; tiles; tiles = tiles->next) {
        pr_rect_t inter = rect_intersection(tiles->rect, r);
        if (rect_valid(inter)) {
            tile_prepend(&result, inter);
            n++;
        }
    }

    if (count) *count = n;
    return result;
}

pr_tile_t *pr_merge_tiles(pr_tile_t *a, const pr_tile_t *b)
{
    pr_tile_t *tail = a;
    if (!tail) return pr_clone_tiles(b);

    while (tail->next) tail = tail->next;

    for (; b; b = b->next) {
        pr_tile_t *t = pr_get_tile();
        if (!t) return a;
        t->rect = b->rect;
        tail->next = t;
        tail = t;
    }
    return a;
}

static int tiles_can_merge_x(pr_rect_t a, pr_rect_t b)
{
    return a.ul.y == b.ul.y && a.lr.y == b.lr.y &&
           a.lr.x + 1 == b.ul.x;
}

static int tiles_can_merge_y(pr_rect_t a, pr_rect_t b)
{
    return a.ul.x == b.ul.x && a.lr.x == b.lr.x &&
           a.lr.y + 1 == b.ul.y;
}

static int tile_compare(const void *ap, const void *bp)
{
    const pr_tile_t *a = *(const pr_tile_t **)ap;
    const pr_tile_t *b = *(const pr_tile_t **)bp;
    if (a->rect.ul.y != b->rect.ul.y)
        return (a->rect.ul.y > b->rect.ul.y) ? 1 : -1;
    if (a->rect.ul.x != b->rect.ul.x)
        return (a->rect.ul.x > b->rect.ul.x) ? 1 : -1;
    return 0;
}

pr_tile_t *pr_coalesce_tiles(pr_tile_t *tiles)
{
    if (!tiles) return NULL;

    size_t n = 0;
    for (pr_tile_t *t = tiles; t; t = t->next) n++;
    if (n < 2) return tiles;

    pr_tile_t **arr = (pr_tile_t **)malloc(n * sizeof(pr_tile_t *));
    if (!arr) return tiles;

    size_t i = 0;
    for (pr_tile_t *t = tiles; t; t = t->next) arr[i++] = t;

    qsort(arr, n, sizeof(pr_tile_t *), tile_compare);

    size_t out = 0;
    for (i = 0; i < n; i++) {
        if (out > 0 && tiles_can_merge_x(arr[out-1]->rect, arr[i]->rect)) {
            arr[out-1]->rect.lr.x = arr[i]->rect.lr.x;
            arr[i]->next = NULL;
            pr_free_tiles(arr[i]);
            arr[i] = NULL;
        } else if (out > 0 &&
                   tiles_can_merge_y(arr[out-1]->rect, arr[i]->rect)) {
            arr[out-1]->rect.lr.y = arr[i]->rect.lr.y;
            arr[i]->next = NULL;
            pr_free_tiles(arr[i]);
            arr[i] = NULL;
        } else {
            arr[out++] = arr[i];
        }
    }

    for (i = 0; i < out - 1; i++)
        arr[i]->next = arr[i + 1];
    if (out > 0)
        arr[out - 1]->next = NULL;

    pr_tile_t *result = (out > 0) ? arr[0] : NULL;
    free(arr);
    return result;
}

pr_tile_t *pr_translate_tiles(pr_tile_t *tiles, int16_t dx, int16_t dy)
{
    for (pr_tile_t *t = tiles; t; t = t->next) {
        t->rect.ul.x += dx;
        t->rect.ul.y += dy;
        t->rect.lr.x += dx;
        t->rect.lr.y += dy;
    }
    return tiles;
}

pr_tile_t *pr_de_translate_tiles(pr_tile_t *tiles, int16_t dx, int16_t dy)
{
    return pr_translate_tiles(tiles, -dx, -dy);
}

size_t pr_tile_count(const pr_tile_t *tiles)
{
    size_t n = 0;
    for (; tiles; tiles = tiles->next) n++;
    return n;
}

int pr_tiles_equal(const pr_tile_t *a, const pr_tile_t *b)
{
    while (a && b) {
        if (!rect_equal(a->rect, b->rect)) return 0;
        a = a->next;
        b = b->next;
    }
    return (!a && !b);
}

pr_tile_t *pr_rects_to_tiles(const pr_rect_t *rects, uint16_t count, uint16_t *n)
{
    pr_tile_t *result = NULL;
    uint16_t out = 0;
    for (uint16_t i = 0; i < count; i++) {
        if (rect_valid(rects[i])) {
            tile_prepend(&result, rects[i]);
            out++;
        }
    }
    if (n) *n = out;
    return result;
}

uint16_t pr_tiles_to_rects(const pr_tile_t *tiles, pr_rect_t *rects, uint16_t max)
{
    uint16_t n = 0;
    for (; tiles && n < max; tiles = tiles->next)
        rects[n++] = tiles->rect;
    return n;
}

pr_tile_t *pr_calculate_visible_tiles(pr_rect_t region_rect,
                                       const pr_tile_t *opaque_in_front)
{
    if (!rect_valid(region_rect)) return NULL;

    pr_tile_t *visible = pr_rect_to_tile(region_rect);
    if (!visible) return NULL;
    if (!opaque_in_front) return visible;

    visible = pr_clip_tilings(visible, opaque_in_front, NULL);

    return pr_coalesce_tiles(visible);
}

int pr_region_is_empty(const pr_tile_t *tiles)
{
    return tiles == NULL;
}

pr_rect_t pr_tiles_to_box(const pr_tile_t *tiles)
{
    pr_rect_t box = {{32767, 32767}, {-32768, -32768}};
    if (!tiles) { box.ul.x = box.ul.y = 0; box.lr.x = box.lr.y = -1; return box; }

    for (; tiles; tiles = tiles->next) {
        if (tiles->rect.ul.x < box.ul.x) box.ul.x = tiles->rect.ul.x;
        if (tiles->rect.ul.y < box.ul.y) box.ul.y = tiles->rect.ul.y;
        if (tiles->rect.lr.x > box.lr.x) box.lr.x = tiles->rect.lr.x;
        if (tiles->rect.lr.y > box.lr.y) box.lr.y = tiles->rect.lr.y;
    }
    return box;
}
