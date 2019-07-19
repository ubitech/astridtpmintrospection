#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct
import time
import os
import sys
from tpm_structure import TpmParser
from pprint import *
import StringIO

# arguments
examples = """examples:
    python FILENAME   # trace regular files (default)
    python FILENAME -p 100      # trace PID 100 only
    python FILENAME -b  # trace block devices only
    python FILENAME --comm ls  # trace ls vfs read/write/open operations
    python FILENAME -tr -to  # trace only __vfs_read() and vfs_open()
    python FILENAME -c --filename tpmrm0 --log 'log.txt' # trace /dev/tpmrm0 vfs read/write/open operations and log results to 'log.txt'
""".replace('FILENAME',sys.argv[0])
parser = argparse.ArgumentParser(
    description="Trace 'vfs_open', '__vfs_read' and '__vfs_write'",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
    help="trace this PID only")
parser.add_argument("-cm", "--comm", metavar="comm", dest="comm",
    help="trace specific process name. Max length 14 chars. For 14 or longer we evaluate as startsWith()")
parser.add_argument("-fn", "--filename", metavar="filename", dest="filename",
    help="trace specific filename. Max length 16 chars. For 16 or longer we evaluate as startsWith()")
parser.add_argument("-a", "--all-files", action="store_true",
    help="include non-regular file types (sockets, FIFOs, etc)")
parser.add_argument("-r", "--regular", action="store_true",
    help="include regular files (default if no options given)")
parser.add_argument("-d", "--directory", action="store_true",
    help="include directory files")
parser.add_argument("-c", "--character", action="store_true",
    help="include character devices")
parser.add_argument("-b", "--block", action="store_true",
    help="include block devices")
parser.add_argument("-f", "--fifo", action="store_true",
    help="include FIFO's")
parser.add_argument("-s", "--socket", action="store_true",
    help="include socket")
parser.add_argument("-sl", "--symlink", action="store_true",
    help="include symbolic links")
parser.add_argument("-tr", "--traceread", action="store_true",
    help="trace __vfs_read()")
parser.add_argument("-tw", "--tracewrite", action="store_true",
    help="trace __vfs_write()")
parser.add_argument("-to", "--traceopen", action="store_true",
    help="trace vfs_open()")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-l", "--log", metavar="logfile", dest="log",
    help="log results to file")
args = parser.parse_args()
tgid = args.tgid
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stat.h>

#define MAX_ARRAY_SIZE 1000 //Max buffer array entries, when max is reached we start from 0 (should be enough to avoid race conditions)
#define ARRAY_BUF_SIZE 1024*10 // The maximum buffer size (4096 should be enough but just to be sure)
#define SYNC_INT_READ 0 // index for global variable which stores the buffer indexes for vfs_read()
#define SYNC_INT_WRITE 1 // index for global variable which stores the buffer indexes for vfs_write()
#define STARTED_INDEX 2 // index for global variable which stores an int indicating if we are at our first hook.

enum trace_mode {
    MODE_READ,
    MODE_WRITE,
    MODE_OPEN
};

COMM_CMP_FUNCTION // used for the string comparison function (for comm filtering)

FILENAME_CMP_FUNCTION // used for the string comparison function (for filename/device filtering)

// struct used to store values at hashmap between entry and return point
struct hash_struct {
    ssize_t max_sz;  // the max size of the r/w
    u64 ts;  // timestamp of operation
    u64 name_len;  // in order to pretty print if filename length too long
    unsigned short i_mode;  // the i_mode (type of device and permissions)
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN];  // the filename 
    char comm[TASK_COMM_LEN];  // process name
    void *bufp; // pointer used to read buffer at return kprobe (for vfs_read())
    int sync_index_read; // used to retrieve the correct buffer for vfs_read()
    int sync_index_write; // user to retrieve the correct buffer for vfs_write()
};

// struct used to return data to userland
struct userland_struct {
    enum trace_mode rwo_mode;  // the mode of the operation (r/w/o)
    u32 pid;  // the pid of the process
    ssize_t max_sz;  // the max size of the r/w
    ssize_t real_sz;  // the actual size of the r/w
    u64 delta_us;  // the latency of the operation
    u64 name_len;   // in order to pretty print if filename length too long
    unsigned short i_mode; // the i_mode --> type of file and permissions
    char name[DNAME_INLINE_LEN];  // the filename 
    char comm[TASK_COMM_LEN];  // process name
    int sync_index_read; // used to retrieve the correct buffer for vfs_read()
    int sync_index_write; // user to retrieve the correct buffer for vfs_write()
};

// struct used with a BPF_ARRAY in order to store the buffer data
struct buffer_struct {
    u8 buf[ARRAY_BUF_SIZE];
};

// 3 entryinfo structs to avoid race condition for same pid
BPF_HASH(entryinfo_read, pid_t, struct hash_struct);  // hashmap, used to move data from entry to return kprobes (for vfs_read())
BPF_HASH(entryinfo_write, pid_t, struct hash_struct);  // hashmap, used to move data from entry to return kprobes (for vfs_write())
BPF_HASH(entryinfo_open, pid_t, struct hash_struct);  // hashmap, used to move data from entry to return kprobes (for vfs_open())

// 2 buffer array structs that store buffer data to avoid race condition between reads and writes
BPF_ARRAY(buffer_array_read, struct buffer_struct, MAX_ARRAY_SIZE); // a BPF_ARRAY used to store the buffer data (for vfs_read())
BPF_ARRAY(buffer_array_write, struct buffer_struct, MAX_ARRAY_SIZE); // a BPF_ARRAY used to store the buffer data (for vfs_write())

BPF_ARRAY(globals, int, 3); // Globals array which stores the index used at the buffer BPF_ARRAY for vfs_read() and vfs_write() as a well as a 'first hook' bool value
BPF_PERF_OUTPUT(events);


//------------------ VFS_READ() TRACING -----------------
int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, loff_t *pos)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (TGID_FILTER)  // filter by tgid
        return 0;
    if (TGID_SELF)  // do not trace self
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    // skip I/O lacking a filename and filter by device type if needed
    struct dentry *de = file->f_path.dentry;
    int i_mode = file->f_inode->i_mode;
    if (de->d_name.len == 0 || TYPE_FILTER)     
        return 0;

    // store required info at hash_struct struct
    struct hash_struct hstruct = {}; 
    bpf_get_current_comm(&hstruct.comm, sizeof(hstruct.comm));  // store process name
    struct qstr d_name = de->d_name;
    bpf_probe_read(&hstruct.name, sizeof(hstruct.name), d_name.name);  // store filename

    size_t comm_size; // calculate size of comm (with max 14)
    // max 14 was concluded based on the info returned during debugging
    for(comm_size=0; comm_size<TASK_COMM_LEN-2; comm_size++)
    {
        if (hstruct.comm[comm_size] == '\\00')
        {
            break;
        } 
    }

    size_t name_size; // calculate size of name (with max 16)
    // max 16 due to loop limitations. Testing showed that we can loop until the 16th index
    // We could also use 'd_name.len' and cut at 16
    for(name_size=0; name_size<16; name_size++)
    {
        if (hstruct.name[name_size] == '\\00')
        {
            break;
        } 
    }

    if(COMM_FILTER)  // fiter by process name if needed
        return 0;
    if(FILENAME_FILTER) // filter by filename if needed
        return 0;

    hstruct.max_sz = count;  // store max size of read
    hstruct.ts = bpf_ktime_get_ns();  // store timestamp
    hstruct.i_mode = i_mode;  // store i_mode
    hstruct.name_len = d_name.len;  // store filename length

    int sync_read_index = SYNC_INT_READ;  
    int *read_sync_val = globals.lookup(&sync_read_index); // retrieve current read sync index
    int sync_write_index = SYNC_INT_WRITE;  
    int *write_sync_val = globals.lookup(&sync_write_index); // retrieve current write sync index
    int started_index = STARTED_INDEX;  
    int *started_val = globals.lookup(&started_index); // retrieve current started value
    if (read_sync_val && write_sync_val && started_val) // this is always true, but is needed
    {
        if (*started_val == 1) //if this is not the first time
        {
            // if no resync is needed (r_index = w_index-1)
            if( ( *read_sync_val == (*write_sync_val)-1 ) || ( *read_sync_val == MAX_ARRAY_SIZE-1 && *write_sync_val == 0 ) )
            {
                hstruct.sync_index_read = *read_sync_val;
                (*read_sync_val)++; // increment sync index 
            }
            
            // if we must resync
            else
            {
                *read_sync_val = *write_sync_val;
                hstruct.sync_index_read = *read_sync_val;
            }
        }

        else // if first hook continue normally
        {
            *started_val = 1;
            hstruct.sync_index_read = *read_sync_val;
            (*read_sync_val)++; // increment sync index
        }

        if (*read_sync_val > MAX_ARRAY_SIZE-1) // check if we have exceeded the buffer array length
        {
            *read_sync_val = 0;
        }
    }
    hstruct.bufp = buf; //store pointer to destination buffer
    entryinfo_read.update(&pid, &hstruct);  // add struct to hashmap using pid as unique key
    return 0;
}


int trace_read_return(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, loff_t *pos)
{
    struct hash_struct *hstructp;
    u32 pid = bpf_get_current_pid_tgid();  // read pid
    hstructp = entryinfo_read.lookup(&pid);  // and retrieve stored info
    if (hstructp == 0) {
         return 0; // missed tracing issue or filtered
     }
    entryinfo_read.delete(&pid);

    // create struct used to return data to userland
    struct userland_struct data = {};
    ssize_t actual_size = (ssize_t) PT_REGS_RC(ctx); // read actual bytes read
    if (actual_size < 0) // case of unsuccessfull read
    {
        return 0;
    }
    
    u64 delta_us = (bpf_ktime_get_ns() - hstructp->ts) / 1000;  // calculate latency
    data.max_sz = hstructp->max_sz; // store max size of read
    data.real_sz = actual_size;  // store the actual num of bytes read 
    ssize_t bpf_size =  actual_size; // bytes read from 'buf' due to size limitations
    data.i_mode = hstructp->i_mode;   // store i_mode
    data.rwo_mode = MODE_READ;  // store operation type (READ)
    data.pid = pid;  // store pid
    data.delta_us = delta_us;  // store latency
    data.name_len = hstructp->name_len;  // store filename length
    bpf_probe_read(&data.name, sizeof(data.name), hstructp->name);   // store filename
    bpf_probe_read(&data.comm, sizeof(data.comm), hstructp->comm);  // store process name

    // this check is needed since the data read could be bigger in size than our buffer
    if (bpf_size > ARRAY_BUF_SIZE)
    {
        bpf_size = ARRAY_BUF_SIZE;

    }

    data.sync_index_read = hstructp->sync_index_read; // store current sync index
    struct buffer_struct *buf_structp; // get pointer to buffer struct based on current index
    buf_structp = buffer_array_read.lookup(&data.sync_index_read);
    if (buf_structp)
    {
        
        // for vfs_read the data is copied to the buffer, so we read at return
        bpf_probe_read(&buf_structp->buf, bpf_size, hstructp->bufp);               
    }

    events.perf_submit(ctx, &data, sizeof(data));  // submit data to userland

    return 0;
}

//------------------ VFS_WRITE() TRACING -----------------
int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, loff_t *pos)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    
    if (TGID_FILTER)  // filter by tgid
        return 0;
    if (TGID_SELF)  // do not trace self
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    // skip I/O lacking a filename and filter by device type if needed
    struct dentry *de = file->f_path.dentry;
    int i_mode = file->f_inode->i_mode;
    if (de->d_name.len == 0 || TYPE_FILTER)     
        return 0;

    // store required info at hash_struct struct
    struct hash_struct hstruct = {}; 
    bpf_get_current_comm(&hstruct.comm, sizeof(hstruct.comm));  // store process name
    struct qstr d_name = de->d_name;
    bpf_probe_read(&hstruct.name, sizeof(hstruct.name), d_name.name);  // store filename

    size_t comm_size; // calculate size of comm (with max 14)
    // max 14 was concluded based on the info returned during debugging
    for(comm_size=0; comm_size<TASK_COMM_LEN-2; comm_size++)
    {
        if (hstruct.comm[comm_size] == '\\00')
        {
            break;
        } 
    }

    size_t name_size; // calculate size of name (with max 16)
    // max 16 due to loop limitations. Testing showed that we can loop until the 16th index
    // We could also use 'd_name.len' and cut at 16
    for(name_size=0; name_size<16; name_size++)
    {
        if (hstruct.name[name_size] == '\\00')
        {
            break;
        } 
    }

    if(COMM_FILTER)  // fiter by process name if needed
        return 0;
    if(FILENAME_FILTER) // filter by filename if needed
        return 0;

    hstruct.max_sz = count;  // store max size of write
    hstruct.ts = bpf_ktime_get_ns();  // store timestamp
    hstruct.i_mode = i_mode;  // store i_mode
    hstruct.name_len = d_name.len;  // store filename length

    
    int sync_write_index = SYNC_INT_WRITE;  
    int *write_sync_val = globals.lookup(&sync_write_index); // retrieve current write sync index
    int started_index = STARTED_INDEX;  
    int *started_val = globals.lookup(&started_index); // retrieve current started value
    if (write_sync_val && started_val) // this is always true, but is needed
    {
        if (*started_val != 1) //if this is the first hook note it.
        {
            *started_val=1;
        }

        hstruct.sync_index_write = *write_sync_val;
        (*write_sync_val)++; // increment sync index
        if (*write_sync_val > MAX_ARRAY_SIZE-1) // check if we have exceeded the buffer array length
        {
            *write_sync_val = 0;
        }       
    }

    struct buffer_struct *buf_structp; // get pointer to buffer struct based on current index
    buf_structp = buffer_array_write.lookup(&hstruct.sync_index_write);
    if(buf_structp)
    {
        if ( count < ARRAY_BUF_SIZE )  //case data to be written smaller than our defined buffer
        {
            bpf_probe_read(&buf_structp->buf, count, buf); 
        }
        else // copy ARRAY_BUF_SIZE data at most
        {
            bpf_probe_read(&buf_structp->buf, ARRAY_BUF_SIZE, buf);
        }
    }
    entryinfo_write.update(&pid, &hstruct);  // add struct to hashmap using pid as unique key    
    
    return 0;
}

int trace_write_return(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, loff_t *pos)
{
    struct hash_struct *hstructp;
    u32 pid = bpf_get_current_pid_tgid();  // read pid
    hstructp = entryinfo_write.lookup(&pid);  // and retrieve stored info
    if (hstructp == 0) {
       return 0; // missed tracing issue or filtered
    }
    entryinfo_write.delete(&pid);
    
    // create struct used to return data to userland
    struct userland_struct data = {};
    ssize_t actual_size = (ssize_t) PT_REGS_RC(ctx); // read actual bytes written
    if (actual_size < 0) // case of unsuccessfull read write
    {
        return 0;
    }

    u64 delta_us = (bpf_ktime_get_ns() - hstructp->ts) / 1000;  // calculate latency
    data.max_sz = hstructp->max_sz; // store max size of write
    data.real_sz = actual_size;  // store the actual num of bytes written 
    data.i_mode = hstructp->i_mode;   // store i_mode
    data.rwo_mode = MODE_WRITE;  // store operation type (WRITE)
    data.pid = pid;  // store pid
    data.delta_us = delta_us;  // store latency
    data.name_len = hstructp->name_len;  // store filename length
    bpf_probe_read(&data.name, sizeof(data.name), hstructp->name);   // store filename
    bpf_probe_read(&data.comm, sizeof(data.comm), hstructp->comm);  // store process name

    data.sync_index_write = hstructp->sync_index_write;  // store current sync index
    //NOTE: for vfs_write the data has already been read from the buffer at the entry kprobe
    events.perf_submit(ctx, &data, sizeof(data));  // submit data to userland

    return 0;
}

//------------------ VFS_OPEN() TRACING -----------------
int trace_open(struct pt_regs *ctx, const struct path *path, struct file *file, const struct cred *cred)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (TGID_FILTER)  // filter by tgid
        return 0;
    if (TGID_SELF)  // do not trace self
        return 0;

    u32 pid = bpf_get_current_pid_tgid(); // read pid

    // skip I/O lacking a filename or not of the defined type
    struct dentry *de = path->dentry;
    unsigned short i_mode = path->dentry->d_inode->i_mode;
    if (de->d_name.len == 0 || (TYPE_FILTER)) 
        return 0;

    // store required info at hash_struct struct
    struct hash_struct hstruct = {};
    bpf_get_current_comm(&hstruct.comm, sizeof(hstruct.comm));  // store processname
    struct qstr d_name = de->d_name; 
    bpf_probe_read(&hstruct.name, sizeof(hstruct.name), d_name.name); // store filename
    
    size_t comm_size; // calculate size of comm (with max 14)
    // max 14 was concluded based on the info returned during debugging
    for(comm_size=0; comm_size<TASK_COMM_LEN-2; comm_size++)
    {
        if (hstruct.comm[comm_size] == '\\00')
        {
            break;
        } 
    }

    size_t name_size; // calculate size of name (with max 16)
    // max 16 due to loop limitations. Testing showed that we can loop until the 16 index
    // We could also use 'd_name.len' and cut at 16
    for(name_size=0; name_size<16; name_size++)
    {
        if (hstruct.name[name_size] == '\\00')
        {
            break;
        } 
    }

    if(COMM_FILTER)  // fiter by process name if needed
        return 0;
    if(FILENAME_FILTER) // filter by filename if needed
        return 0;
    
    hstruct.ts = bpf_ktime_get_ns(); // store timestamp
    hstruct.i_mode = i_mode;  // store i_mode
    hstruct.name_len = d_name.len;  // store filename length
    entryinfo_open.update(&pid, &hstruct); // add struct to hashmap using pid as unique key
    return 0;
}


int trace_open_return(struct pt_regs *ctx)
{
    struct hash_struct *hstructp;
    u32 pid = bpf_get_current_pid_tgid();  // read pid
    hstructp = entryinfo_open.lookup(&pid);  // read stored hstructure based on pid
    if (hstructp == 0) {
        // missed tracing issue or filtered
        return 0;
    }
    u64 delta_us = (bpf_ktime_get_ns() - hstructp->ts) / 1000;  // calculate latency
    entryinfo_open.delete(&pid);  // delete entry from hashmap

    struct userland_struct data = {};
    data.i_mode = hstructp->i_mode;   // store i_mode
    data.pid = pid;  // store pid
    data.delta_us = delta_us;  // store latency
    data.rwo_mode = MODE_OPEN; // store operation mode (OPEN)
    data.name_len = hstructp->name_len;  // store length of filename
    bpf_probe_read(&data.name, sizeof(data.name), hstructp->name);  // store filename
    bpf_probe_read(&data.comm, sizeof(data.comm), hstructp->comm); // store process name

    events.perf_submit(ctx, &data, sizeof(data));  //submit data to userland

    return 0;
}


"""

def generate_string_comparison_function(comp_value,type):
    """
    Function used to generate a string comparison function
        param: comp_value: The value to be compared
        param:type: A value indicating if we have a comm or filename comparison
        returns: The function name, and the function
    """
    max_comparison_size = 16 # this is unfortunately the max value allowed for a loop, so we compare max 16 chars for filename and 14 for comm
    if ( type == "comm" and (len(comp_value) > max_comparison_size-2)): #trim provided value if needed
        comp_value = comp_value[:max_comparison_size-2]
    else:
        comp_value = comp_value[:max_comparison_size]
    max_comparison_size += 1 # for null byte
    print("[i] Comparison Value Evaluated as: '{}'".format(comp_value))
    fname = 'string_comparison_{}'.format(comp_value.encode('hex')[2:20])
    comp_function = """
    static inline bool %s(char * str, size_t str_size) {
    
            char user_str[] = "%s";
            char bpf_string[%s];
            bpf_probe_read(&bpf_string, str_size, (void *)str);
            if (%s != str_size)
            {
                return false;
            }

            for (int i = 0; i<str_size; ++i) {
                if (user_str[i] != bpf_string[i]) {
                    return false;
                }
            }

            return true;
    }
                """ % (fname, comp_value,max_comparison_size, len(comp_value))
    return fname, comp_function


# https://elixir.bootlin.com/linux/v4.7/source/include/uapi/linux/stat.h#L20
def translate_type(i_mode):
    """
    Method used to translate an i_mode to the equivalent type
        param: i_mode: The given i_mode (ushort)
        returns: A string representing the Type of the device
    """
    # CONSTANTS USED
    S_IFMT = 00170000
    S_IFSOCK = 0140000
    S_IFLNK = 0120000
    S_IFREG = 0100000
    S_IFBLK = 0060000
    S_IFDIR = 0040000
    S_IFCHR = 0020000
    S_IFIFO = 0010000
    if (((i_mode) & S_IFMT) == S_IFLNK):
        return 'LNK'
    if (((i_mode) & S_IFMT) == S_IFREG):
        return "REG FILE"
    if (((i_mode) & S_IFMT) == S_IFDIR):
        return  'DIRECTORY'
    if (((i_mode) & S_IFMT) == S_IFCHR):
        return 'CHAR DEVICE'
    if (((i_mode) & S_IFMT) == S_IFBLK):
        return 'BLOCK DEVICE'
    if (((i_mode) & S_IFMT) == S_IFIFO):
        return 'FIFO'
    if (((i_mode) & S_IFMT) == S_IFSOCK):
        return 'SOCK'
    return 'UNDEFINED'


# Arg options parsing
if args.comm:
    fname, comparison_function = generate_string_comparison_function(args.comm,"comm")
    bpf_text = bpf_text.replace('COMM_CMP_FUNCTION',comparison_function)
    bpf_text = bpf_text.replace('COMM_FILTER', '!(({}(hstruct.comm,comm_size)))'.format(fname))
else:
    bpf_text = bpf_text.replace('COMM_FILTER', '0')
    bpf_text = bpf_text.replace('COMM_CMP_FUNCTION','')

if args.filename:
    fname, comparison_function = generate_string_comparison_function(args.filename,"filename")
    bpf_text = bpf_text.replace('FILENAME_CMP_FUNCTION',comparison_function)
    bpf_text = bpf_text.replace('FILENAME_FILTER', '!(({}(hstruct.name,name_size)))'.format(fname))
else:
    bpf_text = bpf_text.replace('FILENAME_FILTER', '0')
    bpf_text = bpf_text.replace('FILENAME_CMP_FUNCTION','')

if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')
if args.all_files:
    bpf_text = bpf_text.replace('TYPE_FILTER', '0')
else:
    types_to_trace = ''
    if args.regular:
        types_to_trace += ' !S_ISREG(i_mode) &&'
    if args.directory:
        types_to_trace += ' !S_ISDIR(i_mode) &&'
    if args.character:
        types_to_trace += ' !S_ISCHR(i_mode) &&'
    if args.block:
        types_to_trace += ' !S_ISBLK(i_mode) &&'
    if args.fifo:
        types_to_trace += ' !S_ISFIFO(i_mode) &&'
    if args.socket:
        types_to_trace += ' !S_ISSOCK(i_mode) &&'
    if args.symlink:
        types_to_trace += ' !S_ISLNK(i_mode) &&'
    types_to_trace = types_to_trace[:-2]
    if types_to_trace == '': # case of no options given
        types_to_trace = '!S_ISREG(i_mode)'  # Default is to trace regular files
    types_to_trace = " ("+types_to_trace+") "  # for correct C syntax (avoid warning)
    bpf_text = bpf_text.replace('TYPE_FILTER', types_to_trace)
bpf_text = bpf_text.replace('TGID_SELF', 'tgid == %d' % os.getpid())


#  Print program in case of debug
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
all_options = not (args.traceopen or args.traceread or args.tracewrite)  # if no options, trace everything
# Hook functions (vfs_open, __vfs_read, __vfs_write)
if (all_options or args.traceopen):
    b.attach_kprobe(event="vfs_open", fn_name="trace_open")
    b.attach_kretprobe(event="vfs_open", fn_name="trace_open_return")
if (all_options or args.traceread):
    b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    b.attach_kretprobe(event="__vfs_read", fn_name="trace_read_return")
if (all_options or args.tracewrite):
    try:
        b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")
        b.attach_kretprobe(event="__vfs_write", fn_name="trace_write_return")
    except:
        # older kernels don't have __vfs_write so try vfs_write instead
        b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
        b.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")

TASK_COMM_LEN = 16  # linux/sched.h
DNAME_INLINE_LEN = 32  # linux/dcache.h

# Userland representation of our struct
class Data(ct.Structure):
    _fields_ = [
        ("rwo_mode", ct.c_int),
        ("pid", ct.c_uint),
        ("max_sz", ct.c_ssize_t),
        ("real_sz", ct.c_ssize_t),
        ("delta_us", ct.c_ulonglong),
        ("name_len", ct.c_ulonglong),
        ("i_mode", ct.c_ushort),
        ("name", ct.c_char * DNAME_INLINE_LEN),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("sync_index_read", ct.c_int),
        ("sync_index_write", ct.c_int),
    ]



# Mode translation (read, write, open)
mode_s = {
    0: 'R',
    1: 'W',
    2: 'O'
}

# print Header Columns
print("{:8s} {:16s} {:6s} {:5s} {:15s} {:9s} {:14s} {:32s} {:64s}".format("TIME(s)", "COMM", "TID", "MODE",
    "BYTES", "LAT(ms)", "DEVICE TYPE", "FILENAME", "DATA"))
start_ts = time.time()  # in order to have a time trail for our program
tpm_parser = TpmParser()  # Tpm parser object used to translate serialized commands towards and from the TPM
current_write_index = -1
current_read_index = -1

def print_event(cpu, data, size):
    """
    Method responsible for printing the events received from kerneland
    """
    global current_write_index, current_read_index
    data_to_print = ''
    event = ct.cast(data, ct.POINTER(Data)).contents  # Cast data to appropriate format
    ms = float(event.delta_us) / 1000
    name = event.name.decode()  # read file/device name and trim if necessary
    if event.name_len > DNAME_INLINE_LEN:
        name = name[:-3] + "..."

    buf = ''
    if mode_s[event.rwo_mode] == 'R':
        buf = b["buffer_array_read"][event.sync_index_read].buf  # read buffer and format appropriately

    elif mode_s[event.rwo_mode] == 'W':
        buf = b["buffer_array_write"][event.sync_index_write].buf  # read buffer and format appropriately
    
    if event.real_sz < len(buf):  # trim buf appropriately
        buf = buf[:event.real_sz]
    data = ''
    for index in range(len(buf)):
        data+=chr(buf[index])
    string_escaped_data = data.encode('string_escape')
    data_list = [string_escaped_data[idx:idx+64] for idx,val in enumerate(string_escaped_data) if idx%64 == 0]  # split data every 64 bytes
    if not data_list:  # case of no data
        data_list = ['']

    data_to_print += "\n{:<8.3f} {:<16.14s} {:<6d} {:<5s} {:<15s} {:<9.2f} {:<14s} {:<32s} {:<64s}\n".format(
        time.time() - start_ts, event.comm.decode(), event.pid,
        mode_s[event.rwo_mode], "{} of {}".format(event.real_sz,event.max_sz), ms, translate_type(event.i_mode),  name, data_list[0])
    # pretty print data
    for index, value in enumerate(data_list):
        if index == 0:
            continue
        if index == len(data_list)-1:
            data_to_print += "{:>113s}{:<64s}\n".format('',value)
        else:
            data_to_print += "{:>177s}\n".format(value)

    # Try to translate commands send to and received from the TPM
    try:
        if mode_s[event.rwo_mode] == 'W':  # Case of command towards the tpm
            current_write_index = event.sync_index_write
            tpm_parser.tpm_command = data  # Initialize tpm parser and parse
            tpm_parser.offset = 0
            parsed_command = tpm_parser.parse(event.pid, 'W', write_index=event.sync_index_write)
            if parsed_command:
                data_to_print+= "[i] MANAGED TO PARSE COMMAND SEND TO TPM!!\n"
                data_to_print += pformat(parsed_command)
        elif mode_s[event.rwo_mode] == 'R':  # Case of response
            current_read_index = event.sync_index_read
            # print(value)
            if (current_read_index == current_write_index):
                tpm_parser.tpm_command = data  # Initialize tpm parser and parse
                tpm_parser.offset = 0
                parsed_command = tpm_parser.parse(event.pid, 'R', read_index=event.sync_index_read)
                if parsed_command:
                    data_to_print += "[i] MANAGED TO PARSE COMMAND RECEIVED FROM TPM!!\n"
                    data_to_print += pformat(parsed_command)
    except Exception as ex:
        print("[E] {}".format(ex))  #!debug
          # pass

    data_to_print += "\n"+"-"*177
    print(data_to_print)

    if args.log: # log if requested
        fd = open(args.log,'a')
        fd.write(data_to_print)
        fd.close()

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()
