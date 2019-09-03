#include "test_defs.h"

//http://selinuxproject.org/page/NB_AL#General_SELinux_Audit_Events


static ExampleRec ex_sel_avc_denied1 = {1400, "audit(1242575005.122:101): avc: denied { rename } for pid=2508 comm=\"canberra-gtk-pl\" name=\"c73a516004b572d8c845c74c49b2511d:runtime.tmp\" dev=dm-0 ino=188999 scontext=test_u:staff_r:oddjob_mkhomedir_t:s0 tcontext=test_u:object_r:gnome_home_t:s0 tclass=lnk_file"};

static ExampleRec ex_sel_avc_granted1 = {1400,"audit(1239116352.727:311): avc: granted { transition } for pid=7687 comm=\"bash\" path=\"/usr/move_file/move_file_c\" dev=dm-0 ino=402139 scontext=unconfined_u:unconfined_r:unconfined_t tcontext=unconfined_u:unconfined_r:move_file_t tclass=process"};
static ExampleRec ex_sel_policy1 = {1403,"audit(1336662937.117:394): policy loaded auid=0 ses=2"};
static ExampleRec ex_sel_user_avc1 = {1167, "audit(1267534395.930:19): user pid=1169 uid=0 auid=4294967295 ses=4294967295 subj=system_u:unconfined_r:unconfined_t msg='avc: denied { read } for request=SELinux:SELinuxGetClientContext comm=X-setest resid=3c00001 restype=<unknown> scontext=unconfined_u:unconfined_r:x_select_paste_t tcontext=unconfined_u:unconfined_r:unconfined_t tclass=x_resource : exe=\"/usr/bin/Xorg\" sauid=0 hostname=? addr=? terminal=?'"};
static ExampleRec ex_sel_netlabel1 = {1416,"audit(1336664587.640:413): netlabel: auid=0 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 netif=lo src=127.0.0.1 sec_obj=system_u:object_r:unconfined_t:s0-s0:c0,c100 res=1"};

static std::vector<ExampleRec> ex_sel_records1 ={
  ex_sel_avc_denied1
,{1400, "audit(1242575005.122:101): avc: denied { unlink } for pid=2508 comm=\"canberra-gtk-pl\" name=\"c73a516004b572d8c845c74c49b2511d:runtime\" dev=dm-0 ino=188578 scontext=test_u:staff_r:oddjob_mkhomedir_t:s0 tcontext=system_u:object_r:gnome_home_t:s0 tclass=lnk_file"}
,{1300, "audit(1242575005.122:101): arch=40000003 syscall=38 success=yes exit=0 a0=82d2760 a1=82d2850 a2=da6660 a3=82cb550 items=0 ppid=2179 pid=2508 auid=500 uid=500 gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500 tty=(none) ses=1 comm=\"canberra-gtk-pl\" exe=\"/usr/bin/canberra-gtk-play\" subj=test_u:staff_r:oddjob_mkhomedir_t:s0 key=(null)"}
,ex_sel_user_avc1
,ex_sel_netlabel1
,ex_sel_policy1
,ex_sel_avc_granted1
};
