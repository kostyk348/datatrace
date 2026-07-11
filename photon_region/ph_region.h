#ifndef PH_REGION_H
#define PH_REGION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct { int16_t x, y; }           pr_point_t;
typedef struct { pr_point_t ul, lr; }       pr_rect_t;
typedef struct pr_tile { pr_rect_t rect; struct pr_tile *next; } pr_tile_t;

#define pr_rect_empty(r)  ((r).lr.x < (r).ul.x || (r).lr.y < (r).ul.y)
#define pr_rect_width(r)  ((r).lr.x - (r).ul.x + 1)
#define pr_rect_height(r) ((r).lr.y - (r).ul.y + 1)

pr_rect_t pr_rect_intersection(pr_rect_t a, pr_rect_t b);
int       pr_rect_intersects(pr_rect_t a, pr_rect_t b);
int       pr_rect_contains(pr_rect_t a, pr_rect_t b);

pr_tile_t *pr_get_tile(void);
void       pr_free_tiles(pr_tile_t *tiles);

pr_tile_t *pr_clone_tiles(const pr_tile_t *tiles);

pr_tile_t *pr_rect_to_tile(pr_rect_t r);

pr_tile_t *pr_clip_tilings(pr_tile_t *tiles,
                            const pr_tile_t *clip_tiles,
                            pr_tile_t **intersection);

pr_tile_t *pr_subtract_tilings(pr_tile_t *tiles,
                                const pr_tile_t *clip_tiles);

pr_tile_t *pr_subtract_rect(pr_tile_t *tiles, pr_rect_t clip_rect);

pr_tile_t *pr_intersect_tilings(const pr_tile_t *a,
                                 const pr_tile_t *b,
                                 uint16_t *count);

pr_tile_t *pr_intersect_rect(const pr_tile_t *tiles, pr_rect_t r,
                              uint16_t *count);

pr_tile_t *pr_merge_tiles(pr_tile_t *a, const pr_tile_t *b);
pr_tile_t *pr_coalesce_tiles(pr_tile_t *tiles);

pr_tile_t *pr_translate_tiles(pr_tile_t *tiles, int16_t dx, int16_t dy);
pr_tile_t *pr_de_translate_tiles(pr_tile_t *tiles, int16_t dx, int16_t dy);

size_t     pr_tile_count(const pr_tile_t *tiles);
int        pr_tiles_equal(const pr_tile_t *a, const pr_tile_t *b);

pr_tile_t *pr_rects_to_tiles(const pr_rect_t *rects, uint16_t count, uint16_t *n);
uint16_t   pr_tiles_to_rects(const pr_tile_t *tiles, pr_rect_t *rects, uint16_t max);

pr_tile_t *pr_calculate_visible_tiles(pr_rect_t region_rect,
                                       const pr_tile_t *opaque_in_front);

int        pr_region_is_empty(const pr_tile_t *tiles);
pr_rect_t  pr_tiles_to_box(const pr_tile_t *tiles);

#ifdef __cplusplus
}
#endif

#endif
