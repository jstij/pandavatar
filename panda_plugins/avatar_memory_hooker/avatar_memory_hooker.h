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

#ifndef PANDAVATAR_REMOTE_MEMORY_H
#define PANDAVATAR_REMOTE_MEMORY_H

#include <queue>

extern "C" {
#include <qemu-thread.h>
}

#include "cajun/json/reader.h"
#include "QemuSocket.h"
    
class RemoteMemoryInterface
{
public:
    RemoteMemoryInterface(std::string sockAddress, bool verbose = false);
    virtual ~RemoteMemoryInterface();
    void writeMemory(uint32_t address, int size, uint64_t value);
    uint64_t readMemory(uint32_t address, int size);
    
    void parse(std::string& token); // & bedeutet er reicht nur Pointer weiter
    
private:
    static void * receiveThread(void *);
    void handleClientCommand(std::string cmd, json::Object* params);
    
    QemuMutex m_mutex;  // m_ nur weil manche es so machen um member variablen zu erkennen (nicht mehr so in)
    QemuCond m_responseCond;
    QemuThread m_thread;
    //std::queue<std::tr1::shared_ptr<json::Object> > m_interruptQueue;
    std::queue<json::Object*> m_responseQueue;
    bool m_cancelThread;
    QemuTcpSocket* m_socket;
    bool m_verbose;
};


// class RemoteMemory : public MemoryInterceptor
// {
//     S2E_PLUGIN
// public:
//     RemoteMemory(S2E* s2e): MemoryInterceptor(s2e) {}
//     virtual ~RemoteMemory();

//     void initialize();
    
// private:
//     enum MemoryAccessType {EMemoryAccessType_None, EMemoryAccessType_Read, EMemoryAccessType_Write, EMemoryAccessType_Execute};
    
//     /**
//      * Called whenever memory is accessed.
//      * This function checks the arguments and then calls memoryAccessed() with parsed arguments.
//      */
//     virtual klee::ref<klee::Expr> slotMemoryAccess(S2EExecutionState *state,
//         klee::ref<klee::Expr> virtaddr /* virtualAddress */,
//         klee::ref<klee::Expr> hostaddr /* hostAddress */,
//         klee::ref<klee::Expr> value /* value */,
//         int access_type);
    
//     /**
//      * slotMemoryAccess forwards the call to this function after the arguments have been parsed and checked.
//      */
//     uint64_t memoryAccessed(S2EExecutionState *, uint64_t address, int width, uint64_t value, MemoryAccessType type);
    
//     /**
//      * Checks if a command has been received. If so, returns true, otherwise returns false.
//      */
// //    bool receiveCommand(json::Object& command);
//     /**
//      * Blocks until a response has been received.
//      */
// //    void receiveResponse(json::Object& response);
    
//     void slotTranslateInstructionStart(ExecutionSignal* signal, 
//             S2EExecutionState* state,
//             TranslationBlock* tb,
//             uint64_t pc);
//     void slotExecuteInstructionStart(S2EExecutionState* state, uint64_t pc);
    
//     bool m_verbose;
// //    MemoryMonitor * m_memoryMonitor;
// //    std::tr1::shared_ptr<QemuTcpServerSocket> m_serverSocket;
// //    std::tr1::shared_ptr<QemuTcpSocket> m_remoteSocket;
//     std::tr1::shared_ptr<RemoteMemoryInterface> m_remoteInterface;
//     std::vector< std::pair< uint64_t, uint64_t > > ranges;
    
// };

#endif // PANDAVATAR_REMOTE_MEMORY_H
