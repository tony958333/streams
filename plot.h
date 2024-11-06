// https://blog.csdn.net/qq_72157449/article/details/130490332
// https://github.com/libsdl-org/SDL/releases
// https://github.com/libsdl-org/SDL/releases/download/release-2.30.8/SDL2-2.30.8.tar.gz
// version: 2.30.8
// decompress
// ./config ; make ; make install
// gcc sdl.c -l:libSDL2.so
//
#include <SDL2/SDL.h>

#define SCREEN_WIDTH 640
#define SCREEN_HEIGHT 480

static SDL_Window *window = NULL;
static SDL_Renderer *renderer = NULL;
static int screen_width = SCREEN_WIDTH;
static int screen_height = SCREEN_HEIGHT;
static int Ox = 50;
static int Oy = SCREEN_HEIGHT/2;
static int UnitX = 10;
static int UnitY = 10;
static SDL_Color colors[]={ {0,0,0},
                            {255, 255, 255},
                            {255,0,0},
                            {0,255,0},
                            {0,0,255},
                            {255,255,0},
                            {255,0,255},
                            {0,255,255}};
#define BLACK 0
#define WHITE 1
#define RED 2
#define GREEN 3
#define BLUE 4

int plot_text() {
    return 0;
}
int plot_color(int c) {
    return SDL_SetRenderDrawColor(renderer, colors[c].r,colors[c].g,colors[c].b,255);
}
void plot_dot(int x, int y) {
    SDL_RenderDrawLine(renderer,Ox+x*UnitX-1,Oy+y*UnitY,Ox+x*UnitX+1,Oy+y*UnitY);
    SDL_RenderDrawLine(renderer,Ox+x*UnitX,Oy+y*UnitY-1,Ox+x*UnitX,Oy+y*UnitY+1);
}
void plot_dots(int startx,int *ys, int cnt) {
    for (int i=0; i<cnt; i++) {
        SDL_RenderDrawPoint(renderer,Ox+(startx+i)*UnitX,Oy-ys[i]*UnitY);
    }
}
void plot_line(int x1, int y1, int x2, int y2) {
    SDL_RenderDrawLine(renderer, Ox+x1*UnitX, Oy-y1*UnitY, Ox+x2*UnitX, Oy-y2*UnitY);
}
int plot_init(int width, int height, int Ux, int Uy) {
    screen_width = width;
    screen_height = height;
    UnitX=Ux;
    UnitY=Uy;
    Ox=50;
    Oy=screen_height/2;
    if (SDL_Init(SDL_INIT_VIDEO) < 0) {
        printf("SDL_Init: %s\n", SDL_GetError());
        return -1;
    }
    if (SDL_CreateWindowAndRenderer(screen_width, screen_height, SDL_WINDOW_OPENGL, &window, &renderer)<0) {
        printf("SDL_CreateWindowAndRenderer: %s\n", SDL_GetError());
        return -1;
    }
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
    SDL_RenderClear(renderer);
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
    //draw x-axis,y-axis
    plot_line(0,0,screen_width,0);
    plot_line(0,screen_height/2,0,-screen_height/2);
    SDL_RenderDrawLine(renderer, Ox-5, Oy, Ox, Oy);
    for (int i=1;i<=screen_height/2/UnitY;i++) {
        SDL_RenderDrawLine(renderer, Ox-5, Oy-i*UnitY, Ox, Oy-i*UnitY);
        SDL_RenderDrawLine(renderer, Ox-5, Oy+i*UnitY, Ox, Oy+i*UnitY);
    }
    return 0;
}
void plot_show() {
    SDL_RenderPresent(renderer);
}
void plot_close() {
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
}
void plot_delay(Uint32 d) {
    SDL_Delay(d*1000);
}

void plot_data() {
    struct streamHeader *st;
    struct in_addr sip,dip;
    plot_init(1024,1024,1,1);
    //
    Uint8 color=1;
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        if (st->num>0) {
            while (st != nullptr) {
                if (st->pktNumber<500) { st=st->next; continue; }
                sip.s_addr=st->sip.ip32;
                dip.s_addr=st->dip.ip32;
                plot_color(color++%7+1);
                //char str[INET_ADDRSTRLEN];
                //inet_ntop(AF_INET,&sip, str, sizeof(str));
                //printf("%lld:hash %x, \033[1;32;40m%s\033[0m:%d",++streamNum,st->hash,str,ntohs(st->sport));
                //char str[INET_ADDRSTRLEN];
                //inet_ntop(AF_INET,&dip, str, sizeof(str));
                //printf(" -> \033[1;32;40m%s\033[0m:%d,pkt number(%d).\n",str,ntohs(st->dport),st->pktNumber);
                int dy;
                for (int j=0;j<st->pktNumber;j++) {
                    dy = st->pktInfo[j].pktlen;
                    if (dy>0) {
                        //dy = 32-__builtin_clz(dy);
                        plot_line(j,dy,j,0);
                    }
                    else if (dy<0) {
                        //dy = __builtin_clz(-dy)-32;
                        plot_line(j,dy,j,0);
                    }
                    else
                        plot_dot(j,0);
                }
                st=st->next;
            }
        }
    }
    plot_show();
    plot_delay(1);
    //pause();
    plot_close();
}
