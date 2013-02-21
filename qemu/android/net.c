#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#include "shaper.h"
#include "net.h"
#include "libslirp.h"


double   qemu_net_upload_speed   = 0.;
double   qemu_net_download_speed = 0.;
int      qemu_net_min_latency = 0;
int      qemu_net_max_latency = 0;
int      qemu_net_disable = 0;

int
ip_packet_is_internal( const uint8_t*  data, size_t  size )
{
    const uint8_t*  end = data + size;
    
    /* must have room for Mac + IP header */
    if (data + 40 > end)
        return 0;
    
    if (data[12] != 0x08 || data[13] != 0x00 )
        return 0;
    
    /* must have valid IP header */
    data += 14;
    if ((data[0] >> 4) != 4 || (data[0] & 15) < 5)
        return 0;
    
    /* internal if both source and dest addresses are in 10.x.x.x */
    return ( data[12] == 10 && data[16] == 10);
}

#ifdef CONFIG_ANDROID

NetShaper  slirp_shaper_in;
NetShaper  slirp_shaper_out;
NetDelay   slirp_delay_in;

static void
slirp_delay_in_cb( void*   data,
                   size_t  size,
                   void*   opaque )
                   {
                       slirp_input( (const uint8_t*)data, (int)size );
                       opaque = opaque;
                   }
                   
                   static void
                   slirp_shaper_in_cb( void*   data,
                                       size_t  size,
                                       void*   opaque )
                                       {
                                           netdelay_send_aux( slirp_delay_in, data, size, opaque );
                                       }
                                       
                                       static void
                                       slirp_shaper_out_cb( void*   data,
                                                            size_t  size,
                                                            void*   opaque )
                                                            {
                                                                qemu_send_packet( slirp_vc, (const uint8_t*)data, (int)size );
                                                            }
                                                            
                                                            void
                                                            slirp_init_shapers( void )
                                                            {
                                                                slirp_delay_in   = netdelay_create( slirp_delay_in_cb );
                                                                slirp_shaper_in  = netshaper_create( 1, slirp_shaper_in_cb );
                                                                slirp_shaper_out = netshaper_create( 1, slirp_shaper_out_cb );
                                                                
                                                                netdelay_set_latency( slirp_delay_in, qemu_net_min_latency, qemu_net_max_latency );
                                                                netshaper_set_rate( slirp_shaper_out, qemu_net_download_speed );
                                                                netshaper_set_rate( slirp_shaper_in,  qemu_net_upload_speed  );
                                                            }
                                                            
                                                            #endif /* CONFIG_ANDROID */
                                                            
                                                            
                                                            
                                                            
                                                           
                                                            

                                                            
                                                            #if (0)
                                                            static ssize_t slirp_receive(VLANClientState *vc, const uint8_t *buf, size_t size)
                                                            {
                                                                #ifdef DEBUG_SLIRP
                                                                printf("slirp input:\n");
                                                                hex_dump(stdout, buf, size);
                                                                #endif
                                                                
                                                                #ifdef CONFIG_ANDROID
                                                                netshaper_send(slirp_shaper_in, (char*)buf, size);
                                                                #else
                                                                slirp_input(buf, size);
                                                                #endif
                                                                return size;
                                                            }
                                                            #endif