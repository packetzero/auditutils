// This is for dependency free testing...
// Copied from linux/audit.h instead

#define MAX_AUDIT_MESSAGE_LENGTH    8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1

struct nlmsghdr {
  uint32_t nlmsg_len;
  uint16_t nlmsg_type;
  uint16_t nlmsg_flags;
  uint32_t nlmsg_seq;
  uint32_t nlmsg_pid;
};

struct audit_message {
  nlmsghdr  hdr;
  char      data[MAX_AUDIT_MESSAGE_LENGTH];
};

struct audit_reply {
  int                      type;
  int                      len;
  struct audit_message     msg;
};

/* The netlink messages for the audit system is divided into blocks:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 SE Linux use
 * 1500 - 1599 kernel LSPP events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1799 kernel anomaly records
 * 1800 - 1899 kernel integrity events
 * 1900 - 1999 future kernel use
 * 2000 is for otherwise unclassified kernel audit messages (legacy)
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2999 future user space (maybe integrity labels and related events)
 *
 * Messages from 1000-1199 are bi-directional. 1200-1299 & 2100 - 2999 are
 * exclusively user space. 1300-2099 is kernel --> user space
 * communication.
 */
#define AUDIT_GET               1000    /* Get status */
#define AUDIT_SET               1001    /* Set status (enable/disable/auditd) */
#define AUDIT_LIST              1002    /* List syscall rules -- deprecated */
#define AUDIT_ADD               1003    /* Add syscall rule -- deprecated */
#define AUDIT_DEL               1004    /* Delete syscall rule -- deprecated */
#define AUDIT_USER              1005    /* Message from userspace -- deprecated */
#define AUDIT_LOGIN             1006    /* Define the login id and information */
#define AUDIT_WATCH_INS         1007    /* Insert file/dir watch entry */
#define AUDIT_WATCH_REM         1008    /* Remove file/dir watch entry */
#define AUDIT_WATCH_LIST        1009    /* List all file/dir watches */
#define AUDIT_SIGNAL_INFO       1010    /* Get info about sender of signal to auditd */
#define AUDIT_ADD_RULE          1011    /* Add syscall filtering rule */
#define AUDIT_DEL_RULE          1012    /* Delete syscall filtering rule */
#define AUDIT_LIST_RULES        1013    /* List syscall filtering rules */
#define AUDIT_TRIM              1014    /* Trim junk from watched tree */
#define AUDIT_MAKE_EQUIV        1015    /* Append to watched tree */
#define AUDIT_TTY_GET           1016    /* Get TTY auditing status */
#define AUDIT_TTY_SET           1017    /* Set TTY auditing status */
#define AUDIT_SET_FEATURE       1018    /* Turn an audit feature on or off */
#define AUDIT_GET_FEATURE       1019    /* Get which features are enabled */

#define AUDIT_FIRST_USER_MSG    1100    /* Userspace messages mostly uninteresting to kernel */
#define AUDIT_USER_AVC          1107    /* We filter this differently */
#define AUDIT_USER_TTY          1124    /* Non-ICANON TTY input meaning */
#define AUDIT_LAST_USER_MSG     1199
#define AUDIT_FIRST_USER_MSG2   2100    /* More user space messages */
#define AUDIT_LAST_USER_MSG2    2999

#define AUDIT_DAEMON_START      1200    /* Daemon startup record */
#define AUDIT_DAEMON_END        1201    /* Daemon normal stop record */
#define AUDIT_DAEMON_ABORT      1202    /* Daemon error stop record */
#define AUDIT_DAEMON_CONFIG     1203    /* Daemon config change */

#define AUDIT_SYSCALL           1300    /* Syscall event */
/* #define AUDIT_FS_WATCH       1301     * Deprecated */
#define AUDIT_PATH              1302    /* Filename path information */
#define AUDIT_IPC               1303    /* IPC record */
#define AUDIT_SOCKETCALL        1304    /* sys_socketcall arguments */
#define AUDIT_CONFIG_CHANGE     1305    /* Audit system configuration change */
#define AUDIT_SOCKADDR          1306    /* sockaddr copied as syscall arg */
#define AUDIT_CWD               1307    /* Current working directory */
#define AUDIT_EXECVE            1309    /* execve arguments */
#define AUDIT_IPC_SET_PERM      1311    /* IPC new permissions record type */
#define AUDIT_MQ_OPEN           1312    /* POSIX MQ open record type */
#define AUDIT_MQ_SENDRECV       1313    /* POSIX MQ send/receive record type */
#define AUDIT_MQ_NOTIFY         1314    /* POSIX MQ notify record type */
#define AUDIT_MQ_GETSETATTR     1315    /* POSIX MQ get/set attribute record type */
#define AUDIT_KERNEL_OTHER      1316    /* For use by 3rd party modules */
#define AUDIT_FD_PAIR           1317    /* audit record for pipe/socketpair */
#define AUDIT_OBJ_PID           1318    /* ptrace target */
#define AUDIT_TTY               1319    /* Input on an administrative TTY */
#define AUDIT_EOE               1320    /* End of multi-record event */
#define AUDIT_BPRM_FCAPS        1321    /* Information about fcaps increasing perms */
#define AUDIT_CAPSET            1322    /* Record showing argument to sys_capset */
#define AUDIT_MMAP              1323    /* Record showing descriptor and flags in mmap */
#define AUDIT_NETFILTER_PKT     1324    /* Packets traversing netfilter chains */
#define AUDIT_NETFILTER_CFG     1325    /* Netfilter chain modifications */
#define AUDIT_SECCOMP           1326    /* Secure Computing event */
#define AUDIT_PROCTITLE         1327    /* Proctitle emit event */
#define AUDIT_FEATURE_CHANGE    1328    /* audit log listing feature changes */
#define AUDIT_REPLACE           1329    /* Replace auditd if this packet unanswerd */
#define AUDIT_KERN_MODULE       1330    /* Kernel Module events */
#define AUDIT_FANOTIFY          1331    /* Fanotify access decision */

#define AUDIT_AVC               1400    /* SE Linux avc denial or grant */
#define AUDIT_SELINUX_ERR       1401    /* Internal SE Linux Errors */
#define AUDIT_AVC_PATH          1402    /* dentry, vfsmount pair from avc */
#define AUDIT_MAC_POLICY_LOAD   1403    /* Policy file load */
#define AUDIT_MAC_STATUS        1404    /* Changed enforcing,permissive,off */
#define AUDIT_MAC_CONFIG_CHANGE 1405    /* Changes to booleans */
#define AUDIT_MAC_UNLBL_ALLOW   1406    /* NetLabel: allow unlabeled traffic */
#define AUDIT_MAC_CIPSOV4_ADD   1407    /* NetLabel: add CIPSOv4 DOI entry */
#define AUDIT_MAC_CIPSOV4_DEL   1408    /* NetLabel: del CIPSOv4 DOI entry */
#define AUDIT_MAC_MAP_ADD       1409    /* NetLabel: add LSM domain mapping */
#define AUDIT_MAC_MAP_DEL       1410    /* NetLabel: del LSM domain mapping */
#define AUDIT_MAC_IPSEC_ADDSA   1411    /* Not used */
#define AUDIT_MAC_IPSEC_DELSA   1412    /* Not used  */
#define AUDIT_MAC_IPSEC_ADDSPD  1413    /* Not used */
#define AUDIT_MAC_IPSEC_DELSPD  1414    /* Not used */
#define AUDIT_MAC_IPSEC_EVENT   1415    /* Audit an IPSec event */
#define AUDIT_MAC_UNLBL_STCADD  1416    /* NetLabel: add a static label */
#define AUDIT_MAC_UNLBL_STCDEL  1417    /* NetLabel: del a static label */
#define AUDIT_MAC_CALIPSO_ADD   1418    /* NetLabel: add CALIPSO DOI entry */
#define AUDIT_MAC_CALIPSO_DEL   1419    /* NetLabel: del CALIPSO DOI entry */

#define AUDIT_FIRST_KERN_ANOM_MSG   1700
#define AUDIT_LAST_KERN_ANOM_MSG    1799
#define AUDIT_ANOM_PROMISCUOUS      1700 /* Device changed promiscuous mode */
#define AUDIT_ANOM_ABEND            1701 /* Process ended abnormally */
#define AUDIT_ANOM_LINK             1702 /* Suspicious use of file links */
#define AUDIT_INTEGRITY_DATA        1800 /* Data integrity verification */
#define AUDIT_INTEGRITY_METADATA    1801 /* Metadata integrity verification */
#define AUDIT_INTEGRITY_STATUS      1802 /* Integrity enable status */
#define AUDIT_INTEGRITY_HASH        1803 /* Integrity HASH type */
#define AUDIT_INTEGRITY_PCR         1804 /* PCR invalidation msgs */
#define AUDIT_INTEGRITY_RULE        1805 /* policy rule */

#define AUDIT_KERNEL            2000    /* Asynchronous audit record. NOT A REQUEST. */
