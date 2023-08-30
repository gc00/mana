#ifndef __MTCP_RESTART_PLUGIN_H__
# define __MTCP_RESTART_PLUGIN_H__

// This part is specific to lh_proxy

#include <lower_half_api.h>

// This part is specific to the DMTCP/MTCP restart plugin.

// FIXME:  Remove all PluginInfo references in.h in this directory.
//         Create a new PR/commit for DMTCP, and remove PluginInfo from mtcp.
//         Push the PR into DMTCP master.
//         In the DMTCP submodule, git pull --rebase origin master
//         git submodule update
//         Remove this FIXME comment.
//         Create a new MANA PR from this.
typedef LowerHalfInfo_t PluginInfo;

typedef struct RestoreInfo RestoreInfo;
union ProcMapsArea;
void mtcp_plugin_hook(RestoreInfo *rinfo);
int mtcp_plugin_skip_memory_region_munmap(ProcMapsArea *area,
                                          RestoreInfo *rinfo);
int getCkptImageByDir(RestoreInfo *rinfo,
                      char *buffer,
                      size_t buflen,
                      int rank);
char* getCkptImageByRank(int rank, char **argv);

#endif // #ifndef __MTCP_RESTART_PLUGIN_H__
