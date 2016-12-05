/*
 * PANDAVATAR
 *
 * Copyright (c) 2010-2016, Eurecom, Siemens
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author Jonas Zaddach <zaddach@eurecom.fr>
 * @author Jan Stijohann <jan.stijohann@siemens.com>
 */

extern "C" {  // muss man so machen wenn man C code in CPP benutzen moechte
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu_socket.h>
#include <hw/irq.h>

#include <qint.h>
#include <qstring.h>
#include <qdict.h>
#include <qjson.h>
#include <qemu-thread.h>

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_common.h"

#include "monitor.h"
}

#include "avatar_memory_hooker.h"

#include <cajun/json/reader.h>
#include <cajun/json/writer.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#define LISTEN_ADDRESS "127.0.0.1:5555"

extern "C" {  // wenn wir das mit cpp compilieren, dann wuerde das sonst nicht gefunden werden von PANDA
    bool init_plugin(void *self);
    void uninit_plugin(void *);
    int monitor_callback(Monitor *mon, const char *cmd);
}

int memory_after_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int memory_before_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);


bool memcb_enabled = false;
static bool verbose = false;
static std::vector< std::pair< uint64_t, uint64_t > > addressRanges;
RemoteMemoryInterface* remoteMemoryInterface = NULL;

int memory_before_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    bool ok = false;
    for (std::vector< std::pair< uint64_t, uint64_t > >::iterator itr = addressRanges.begin(), end = addressRanges.end();
         itr != end;
         ++itr) {
        if (addr >= itr->first && addr <= itr->second) {
            ok = true;
            break;
        }
    }

    if (!ok) {
        return 0;
    }

    printf("[PANDA emulator] Before memory write at instruction address %lx. Memory addr. written to: %lx \n", (unsigned long)env->panda_guest_pc, (unsigned long)addr);
    switch(size) {
        case 1: 
            remoteMemoryInterface->writeMemory(addr, size, *(uint8_t *) buf);
            // TODO: check if endianess is a problem
            break;
        case 2: 
            remoteMemoryInterface->writeMemory(addr, size, *(uint16_t *) buf);
            // TODO: check if endianess is a problem
            break;
        case 4: 
            remoteMemoryInterface->writeMemory(addr, size, *(uint32_t *) buf);
            // TODO: check if endianess is a problem
            break;
        case 8: 
            remoteMemoryInterface->writeMemory(addr, size, *(uint64_t *) buf);
            // TODO: check if endianess is a problem
            break;
        default:
            assert(false && "Unexpected data size.");
    }

// #ifdef TARGET_I386

//     if (*(int *)buf == -559038737) {
//         int *my_buffer = malloc(sizeof(int));
//         //                         read from addr    into my_buffer
//         panda_virtual_memory_rw(env, addr, (uint8_t *)my_buffer, (int)sizeof(int), 0);
//         printf("Written value: %x\n", *my_buffer);

//         *my_buffer = 33;
//         //                      write to addr     the data from my_buffer
//         panda_virtual_memory_rw(env, addr, (uint8_t *)my_buffer, (int)sizeof(int), 1);
//         free(my_buffer);
//     }
    
// #endif
    return 0;
}


int memory_after_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    bool ok = false;
    for (std::vector< std::pair< uint64_t, uint64_t > >::iterator itr = addressRanges.begin(), end = addressRanges.end();
         itr != end;
         ++itr) {
        if (addr >=itr->first && addr <= itr->second) {
            ok = true;
            break;
        }
    }

    if (!ok) {
        return 0;
    }
    printf("[PANDA emulator] After memory read at instruction address %lx. Memory addr. read from: %lx. Value: %x \n", (unsigned long)env->panda_guest_pc, (unsigned long)addr, *(int *)buf);
    switch(size) {
        case 1: 
            *(uint8_t *) buf = remoteMemoryInterface->readMemory(addr, size);
            // TODO: check if endianess is a problem
            break;
        case 2: 
            *(uint16_t *) buf = remoteMemoryInterface->readMemory(addr, size);
            // TODO: check if endianess is a problem
            break;
        case 4: 
            *(uint32_t *) buf = remoteMemoryInterface->readMemory(addr, size);
            // TODO: check if endianess is a problem
            break;
        case 8: 
            *(uint64_t *) buf = remoteMemoryInterface->readMemory(addr, size);
            // TODO: check if endianess is a problem
            break;
        default:
            assert(false && "Unexpected data size.");
    }

// #ifdef TARGET_I386
//     if (*(int *)buf == -889275714) {
//         printf("Memory read:%d\n", *(int *)buf);
//     }
// #endif
    return 0;
}


int monitor_callback(Monitor *mon, const char *cmd) {
//#ifdef TARGET_I386
    if (memcb_enabled == false){
        printf("You typed: %s.\n Enabling memory callbacks.\n", cmd);
        panda_do_flush_tb();
        panda_disable_tb_chaining();
        panda_enable_precise_pc();
        panda_enable_memcb();
        memcb_enabled = true;
    }
    else {
        printf("You typed: %s\n. Disabling memory callbacks.\n", cmd);
        panda_do_flush_tb();
        panda_disable_memcb();
        panda_disable_precise_pc();
        panda_enable_tb_chaining();
        memcb_enabled = false;
    }

    //void *plugin_handle = panda_get_plugin_by_name("avatar_memory_hooker.so");
    //panda_enable_plugin(plugin_handle);
//#endif
    return 0;
}

bool init_plugin(void *self) {
    bool start_off = false;
    int i;
    panda_arg_list* args = panda_get_args("avatar_memory_hooker");
    if (args != NULL) {
        start_off = panda_parse_bool(args, "start_off");
        for (i = 0; i < args->nargs; ++i) {
            if (strncmp("range_", args->list[i].key, 6) == 0) {
                char *separator = strchr(args->list[i].value, '_');
                if (!separator) {
                    printf("avatar_memory_hooker: Error in command line parameter specification\n");
                    continue;
                }

                char str_addr[20];
                char str_size[20];
                memset(str_addr, 0, sizeof(str_addr));
                strncpy(str_addr, args->list[i].value, std::min(static_cast<size_t>(separator - args->list[i].value), static_cast<size_t>(sizeof(str_addr) - 1)));
                memset(str_size, 0, sizeof(str_size));
                strncpy(str_size, separator + 1, sizeof(str_size) - 1);
                uint64_t addr = 0;
                uint64_t size = 0;
                sscanf(str_addr, "0x%" PRIx64, &addr);
                sscanf(str_size, "0x%" PRIx64, &size);

                addressRanges.push_back(std::make_pair(addr, addr + size - 1));
                printf("avatar_memory_hooker: INFO: monitoring address range 0x%" PRIx64 ":0x%" PRIx64 "\n", addr, size);
            }
        }
    }
    panda_free_args(args);
    verbose = true; 
    std::string serverSocketAddress = LISTEN_ADDRESS;
    
    remoteMemoryInterface = new RemoteMemoryInterface(serverSocketAddress, verbose); 


    // Don't bother if we're not on x86
//#ifdef TARGET_I386

    // todo: make this dependent on start_off
    panda_cb pcb;

    if (!start_off) {
        panda_do_flush_tb();
        panda_disable_tb_chaining();
        panda_enable_precise_pc();
        panda_enable_memcb();
        memcb_enabled = true;
    }

    //pcb.virt_mem_before_read = memory_before_read_callback;
    pcb.virt_mem_after_read = memory_after_read_callback;
    //panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    
    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    pcb.virt_mem_before_write = memory_before_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

//#endif
    return 1;
}

void uninit_plugin(void *self) {
    //fclose(plugin_log);
    printf("uninit_plugin.\n");
}


static std::string intToHex(uint64_t val)
{
    std::stringstream ss;
    
    ss << "0x" << std::hex << val;
    return ss.str();
}
/*
static uint64_t hexToInt(std::string str)
{
    std::stringstream ss;
    uint64_t val;
    
    ss << str.substr(2, std::string::npos);
    ss >> std::hex >> val;
    
    return val;
}
*/

static uint64_t hexBufToInt(std::string str)
{
    uint64_t val = 0;
    std::stringstream ss;
    
    ss << str;
    ss >> std::hex >> val;

    return val;
}

    
    

RemoteMemoryInterface::RemoteMemoryInterface(std::string remoteSockAddress, bool verbose) 
    : m_cancelThread(false), 
      m_socket(new QemuTcpSocket()),
      m_verbose(verbose)
{   
    qemu_mutex_init(&m_mutex);
    qemu_cond_init(&m_responseCond);
    
    QemuTcpServerSocket serverSock(remoteSockAddress.c_str());
    printf("[RemoteMemory]: Waiting for connection on %s\n", remoteSockAddress.c_str());
    serverSock.accept(*m_socket);
    
    qemu_thread_create(&m_thread, &RemoteMemoryInterface::receiveThread, this);
}

void * RemoteMemoryInterface::receiveThread(void * opaque)
{
    RemoteMemoryInterface * rmi = static_cast<RemoteMemoryInterface *>(opaque);
    while (!rmi->m_cancelThread)
    {
        std::string token;
            
        getline(*rmi->m_socket, token, '\n');
        
        if (token.size() == 0 && !rmi->m_socket->isConnected())
        {
            //TODO: do something to gracefully shutdown qemu (i,.e. unblock main thread, return dummy value, shutdown vm)
            printf("[RemoteMemory] Remote end disconnected, machine is dead\n");
            break;
        }
        
        rmi->parse(token);
    }
    
    return NULL;
}

void RemoteMemoryInterface::parse(std::string& token)
{
    json::Object* jsonObject = new json::Object();

    std::istringstream tokenAsStream(token);
    
    try
    {
        json::Reader::Read(*jsonObject, tokenAsStream);
        
        if(jsonObject->Find("reply") != jsonObject->End())
        {
            //TODO: notify and pass object
            qemu_mutex_lock(&m_mutex);
            m_responseQueue.push(jsonObject);
            qemu_cond_signal(&m_responseCond);
            qemu_mutex_unlock(&m_mutex);
        }
        else
        {
            try
            {
                json::Object::iterator itrCmd = jsonObject->Find("cmd");
                if (itrCmd == jsonObject->End())
                {
                    printf("[RemoteMemory] Received json object that was neither a cmd nor a reply: %s\n", token.c_str());
                    return;
                }
                
                json::String& cmd = itrCmd->element;
                
                handleClientCommand(cmd, jsonObject);
            }
            catch (json::Exception& ex)
            {
                printf("[RemoteMemory] JSON exception while handling a command from the client\n");
            }
        }
    }
    catch (json::Exception& ex)
    {
        printf( "[RemoteMemory] Exception in JSON data: %s\n'", token.c_str());
    }
}

void RemoteMemoryInterface::handleClientCommand(std::string cmd, json::Object* params)
{
    qemu_mutex_lock(&m_mutex);
    qemu_mutex_unlock(&m_mutex);
}

  
/**
 * Calls the remote helper to read a value from memory.
 */
uint64_t RemoteMemoryInterface::readMemory(uint32_t address, int size)
{
     json::Object request;
     json::Object params;
     json::Object cpu_state;
     
     if (m_verbose)
        std::cout << "[RemoteMemory] reading memory from address " << std::hex << address << std::dec << "[" << size << "]" << '\n';
     request.Insert(json::Object::Member("cmd", json::String("read")));  
     
     params.Insert(json::Object::Member("address", json::String(intToHex(address))));
     params.Insert(json::Object::Member("size", json::String(intToHex(size))));
     
     //Build cpu state

     request.Insert(json::Object::Member("params", params));

     qemu_mutex_lock(&m_mutex);
     
     json::Writer::Write(request, *m_socket);
     m_socket->flush();

     qemu_cond_wait(&m_responseCond, &m_mutex);
     
     //TODO: There could be multiple responses, but we assume the first is the right
     json::Object* response = m_responseQueue.front();
     m_responseQueue.pop();
     qemu_mutex_unlock(&m_mutex);
     
     //TODO: No checking if this is the right response, if there is an attribute 'value'
     json::String& strValue = (*response)["value"];
     uint64_t value = hexBufToInt(strValue);
     delete response;
     return value;
}
  
/**
 * Calls the remote helper to write a value to memory.
 * This method returns immediatly, as there is not return value to wait for.
 */
void RemoteMemoryInterface::writeMemory(uint32_t address, int size, uint64_t value)
{
     json::Object request;
     json::Object params;
     json::Object cpu_state;
     
     if (m_verbose)
        std::cout << "[RemoteMemory] writing memory at address " << intToHex(address) << "[" << size << "] = " << intToHex(value) << '\n';
     request.Insert(json::Object::Member("cmd", json::String("write")));
     
     params.Insert(json::Object::Member("value", json::String(intToHex(value))));
         
     
     params.Insert(json::Object::Member("address", json::String(intToHex(address))));
     params.Insert(json::Object::Member("size", json::String(intToHex(size))));
     
     //Build cpu state
     
     request.Insert(json::Object::Member("params", params));

     qemu_mutex_lock(&m_mutex);
     
     json::Writer::Write(request, *m_socket);
     m_socket->flush();
     qemu_mutex_unlock(&m_mutex);
}

RemoteMemoryInterface::~RemoteMemoryInterface()
{
    qemu_cond_destroy(&m_responseCond);
    qemu_mutex_destroy(&m_mutex);
}
