/* Simple game server for DataTrace testing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_ENTITIES 64
#define PORT 9999

typedef struct {
    uint32_t id;
    float x, y, z;
    float vx, vy, vz;
    uint8_t health;
    uint8_t type;
    char name[32];
} Entity;

typedef struct {
    uint32_t count;
    Entity entities[MAX_ENTITIES];
} Snapshot;

typedef struct {
    uint32_t msg_type;
    uint32_t seq;
    uint32_t entity_id;
    uint8_t payload[256];
} Packet;

static Entity* g_entities = NULL;
static int g_num_entities = 0;

static Entity* create_entity(const char* name, float x, float y, float z) {
    Entity* e = (Entity*)calloc(1, sizeof(Entity));
    if (!e) return NULL;
    e->id = g_num_entities++;
    e->x = x; e->y = y; e->z = z;
    e->vx = (float)(rand() % 100) / 10.0f;
    e->vy = (float)(rand() % 100) / 10.0f;
    e->vz = (float)(rand() % 100) / 10.0f;
    e->health = 100;
    e->type = rand() % 3;
    strncpy(e->name, name, sizeof(e->name) - 1);
    return e;
}

static void update_physics() {
    for (int i = 0; i < g_num_entities; i++) {
        g_entities[i].x += g_entities[i].vx * 0.016f;
        g_entities[i].y += g_entities[i].vy * 0.016f;
        g_entities[i].z += g_entities[i].vz * 0.016f;
    }
}

static Snapshot* serialize_world() {
    size_t sz = sizeof(Snapshot);
    Snapshot* snap = (Snapshot*)calloc(1, sz);
    if (!snap) return NULL;
    snap->count = g_num_entities;
    memcpy(snap->entities, g_entities, g_num_entities * sizeof(Entity));
    return snap;
}

static Packet* create_packet(uint32_t msg_type, uint32_t entity_id) {
    Packet* pkt = (Packet*)calloc(1, sizeof(Packet));
    if (!pkt) return NULL;
    pkt->msg_type = msg_type;
    pkt->seq = (uint32_t)rand();
    pkt->entity_id = entity_id;
    memset(pkt->payload, 0xAB, sizeof(pkt->payload));
    return pkt;
}

int main(int argc, char** argv) {
    int sock;
    struct sockaddr_in addr;
    volatile int frame;
    Entity* player;

    srand((unsigned int)time(NULL));
    printf("[game_server] pid=%d starting\n", getpid());
    fflush(stdout);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }

    g_entities = (Entity*)calloc(MAX_ENTITIES, sizeof(Entity));
    if (!g_entities) { perror("calloc"); return 1; }

    player = create_entity("Player", 0, 0, 0);
    create_entity("Enemy1", 100, 0, 50);
    create_entity("Enemy2", -100, 0, -50);
    create_entity("Item_Health", 50, 0, 20);
    (void)player;

    printf("[game_server] created %d entities\n", g_num_entities);
    fflush(stdout);

    for (frame = 0; frame < 100; frame++) {
        Snapshot* snap;
        Packet* pkt;
        int sent;

        update_physics();
        snap = serialize_world();

        pkt = create_packet(1, 0);
        memcpy(pkt->payload, snap,
               sizeof(Snapshot) < sizeof(pkt->payload)
                   ? sizeof(Snapshot) : sizeof(pkt->payload));

        sent = sendto(sock, pkt, sizeof(Packet), 0,
                      (struct sockaddr*)&addr, sizeof(addr));
        if (sent < 0) perror("sendto");

        Packet rpkt;
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        int rc = recvfrom(sock, &rpkt, sizeof(Packet), 0,
                          (struct sockaddr*)&src, &srclen);
        if (rc > 0) {
            printf("[game_server] frame=%d recv msg_type=%d\n",
                   frame, rpkt.msg_type);
        }

        free(snap);
        free(pkt);
        usleep(10000);
    }

    free(g_entities);
    close(sock);
    printf("[game_server] done\n");
    return 0;
}
