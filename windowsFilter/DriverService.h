#pragma once

#include <client/ovpncli.hpp>
#include <winfilter/buffer/buffer.hpp>
#include <winfilter/frame/frame.hpp>
#include <memory>
#include <windows.h>
#include <mutex>

#include "NATService.h"

const int threadNumeber = 2;
const int kDriverIOBufferSize = 2000;

struct DriverIOContext {
  OVERLAPPED overlapped;

  enum IOType {
    TYPE_READ,
    TYPE_WRITE,
	TYPE_QUIT,
	TYPE_WRITE_ACTION,
  } io_type;

  unsigned char buffer[kDriverIOBufferSize];
  unsigned int bufferOffset = 0;
  int buffer_size = kDriverIOBufferSize;

  HANDLE file_handle;
};

class DriverService : public winfilter::ClientAPI::OpenVPNClient::TrangsportFilter {
public:
  DriverService(winfilter::ClientAPI::OpenVPNClient* client);
  virtual ~DriverService();

  bool SnatTranslate(DriverIOContext* context);
  bool DnatTranslate(DriverIOContext* context);



  bool Start();
  void Stop();

  static DWORD WINAPI DriverThread(void*);

protected:
  void Close();

  bool NeedStopLoop();

  void InitFrameBuffer();

  void InitFrameContext();

  virtual bool on_transport_recv(winfilter::BufferAllocated& buf) override;
  void ProcessAllPendingWriteIO();

  DriverIOContext* AllocIOContext();
  void ReleaseIOContext(DriverIOContext* context);

  bool PostDriverIO(DriverIOContext* context);

  void IncreasePendingIOCount();
  void DecreasePendingIOCount();

  void initialDriverThread();

  void closeDriverThread();

  void postQuitMessage();
  void postWriteMessage();

  winfilter::ClientAPI::OpenVPNClient* open_vpn_client_;

  HANDLE driver_file_;
  HANDLE iocp_handle_;

  HANDLE iocp_thread_handle_[threadNumeber];

  bool will_exit_;

  UINT32 iocp_context_count_;

  std::mutex mutexIoCacheContex;
  std::list<DriverIOContext*> cached_io_contexts_;

  std::mutex readLock;

  std::list<winfilter::BufferPtr> cached_buffer_ptrs_;
  std::mutex buffer_lock_;

  NATService* nat_service_;
  
  winfilter::Frame::Context frame_context;

  winfilter::BufferAllocated frame_buffer;

};