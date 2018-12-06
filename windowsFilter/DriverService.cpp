#include "DriverService.h"
#include "DriverDefine.h"
#include "QeeYouWfpLogger.h"


#include <windows.h>

namespace {

const DWORD kVCThreadNameException = 0x406D1388;

typedef struct tagTHREADNAME_INFO {
  DWORD dwType;  // Must be 0x1000.
  LPCSTR szName;  // Pointer to name (in user addr space).
  DWORD dwThreadID;  // Thread ID (-1=caller thread).
  DWORD dwFlags;  // Reserved for future use, must be zero.
} THREADNAME_INFO;

// This function has try handling, so it is separated out of its caller.
void SetNameInternal(DWORD thread_id, const char* name) {
  THREADNAME_INFO info;
  info.dwType = 0x1000;
  info.szName = name;
  info.dwThreadID = thread_id;
  info.dwFlags = 0;

  __try {
    RaiseException(kVCThreadNameException, 0, sizeof(info)/sizeof(DWORD),
                   reinterpret_cast<DWORD_PTR*>(&info));
  } __except(EXCEPTION_CONTINUE_EXECUTION) {
  }
}
}  // namespace

DriverService::DriverService(winfilter::ClientAPI::OpenVPNClient* client)
    : open_vpn_client_(client),
      driver_file_(INVALID_HANDLE_VALUE),
      iocp_handle_(INVALID_HANDLE_VALUE),
      will_exit_(false),
      iocp_context_count_(0),
      nat_service_(nullptr),
	  iocp_thread_handle_{ 0 }{

	InitFrameContext();
}

DriverService::~DriverService() {
}

void DriverService::initialDriverThread()
{
	for (UINT32 index = 0; index < sizeof(iocp_thread_handle_) / sizeof(HANDLE); index++)
	{
		DWORD thread_id;
		iocp_thread_handle_[index] = ::CreateThread(NULL, 0, &DriverService::DriverThread, this, 0, &thread_id);
		if (iocp_thread_handle_[index] == INVALID_HANDLE_VALUE) {
			LOGINFO("DriverService::Create driver io thread failed, error is %u", ::GetLastError());
			break;
		}
	}
}

void DriverService::closeDriverThread()
{	
	for (UINT32 index = 0; index < sizeof(iocp_thread_handle_) / sizeof(HANDLE); index++)
	{
		if (iocp_thread_handle_[index] != INVALID_HANDLE_VALUE) {
			if (::WaitForSingleObject(iocp_thread_handle_[index], 10) == WAIT_TIMEOUT)
			{
				postQuitMessage();

				index = 0;
			}
			else
			{
				::CloseHandle(iocp_thread_handle_[index]);

				iocp_thread_handle_[index] = INVALID_HANDLE_VALUE;
			}
		}
	}
}

bool DriverService::Start() {
  if (driver_file_ != INVALID_HANDLE_VALUE) {
    return true;
  }

  bool success = false;
  do {
    driver_file_ = ::CreateFile(DOS_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (driver_file_ == INVALID_HANDLE_VALUE) {
      LOGINFO("DriverService::Create Driver file failed, error is %u", ::GetLastError());
      break;
    }

    iocp_handle_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (iocp_handle_ == INVALID_HANDLE_VALUE) {
      LOGINFO("DriverService::Create IOCP failed, error is %u", ::GetLastError());
      break;
    }

    if (::CreateIoCompletionPort(driver_file_, iocp_handle_, NULL, 1) != iocp_handle_) {
      LOGINFO("DriverService::Bind Driver file with IOCP failed, error is %u", ::GetLastError());
      break;
    }

	for (UINT32 index = 0; index < 10; index++)
	{
		// 所有就绪以后，投递第一个请求
		DriverIOContext* read_io_context = AllocIOContext();
		read_io_context->file_handle = driver_file_;
		read_io_context->buffer_size = kDriverIOBufferSize;
		read_io_context->io_type = DriverIOContext::TYPE_READ;
		if (!PostDriverIO(read_io_context)) {
			LOGINFO("DriverService::Post first read io failed, error is %u", ::GetLastError());
			delete read_io_context;
			break;
		}
	}

	initialDriverThread();

    success = true;
  } while (0);

  if (!success) {
    Close();
  } else {
    nat_service_ = new NATService;
    nat_service_->SetGatewayIP(inet_addr(open_vpn_client_->connection_info().vpnIp4.c_str()));
    open_vpn_client_->set_transport_filter(this);
  }

  return success;
}

void DriverService::Stop() {
  will_exit_ = true;

  if (driver_file_ != INVALID_HANDLE_VALUE) {
    ::CancelIoEx(driver_file_, NULL);
  }


  closeDriverThread();

  Close();
}

bool DriverService::NeedStopLoop() {
  return will_exit_ && iocp_context_count_ == 0;
}

void DriverService::InitFrameContext()
{
	const size_t payload = 2048;
	const size_t headroom = 512;
	const size_t tailroom = 512;
	const size_t align_block = 16;
	const unsigned int buffer_flags = 0;

	frame_context = winfilter::Frame(winfilter::Frame::Context(headroom, payload, tailroom, 0, align_block, buffer_flags))[winfilter::Frame::READ_TUN];

}

void DriverService::InitFrameBuffer()
{
	frame_context.prepare(frame_buffer);
}

void DriverService::Close() {
  if (driver_file_ != INVALID_HANDLE_VALUE) {
    ::CloseHandle(driver_file_);
    driver_file_ = INVALID_HANDLE_VALUE;
  }

  if (iocp_handle_ != INVALID_HANDLE_VALUE) {
    ::CloseHandle(iocp_handle_);
    iocp_handle_ = INVALID_HANDLE_VALUE;
  }

  // 删除所有IO
  for (auto& item : cached_io_contexts_) {
    delete item;
  }

  cached_io_contexts_.clear();

  cached_buffer_ptrs_.clear();

  if (nat_service_) {
    delete nat_service_;
    nat_service_ = nullptr;
  }
}

bool DriverService::on_transport_recv(winfilter::BufferAllocated& buf) {
  if (will_exit_) {
    return false;
  }

  if (nat_service_->checkIpInNatList(buf.data(), buf.size()))
  {
	  std::lock_guard<std::mutex> lock(buffer_lock_);
	  cached_buffer_ptrs_.push_back(std::move(buf.move_to_ptr()));

	  postWriteMessage();

	  return true;
  }
  else
  {
	  return false;
  }

}

void DriverService::ProcessAllPendingWriteIO() {
  if (cached_buffer_ptrs_.empty() || !buffer_lock_.try_lock()) {
    return;
  }

  for (auto& buf : cached_buffer_ptrs_) {
    DriverIOContext* context = AllocIOContext();
    context->bufferOffset = sizeof(INJECT_BUFF);
    context->file_handle = driver_file_;
    context->io_type = DriverIOContext::TYPE_WRITE;
    memcpy_s(context->buffer + context->bufferOffset, kDriverIOBufferSize - context->bufferOffset, buf->data(), buf->size());
    context->buffer_size = buf->size() + context->bufferOffset;
    buf.reset();

    if (DnatTranslate(context))
    {
      if (!PostDriverIO(context)) {
        ReleaseIOContext(context);
      };
    }
    else
    {
      ReleaseIOContext(context);
    }
  }

  cached_buffer_ptrs_.clear();
  buffer_lock_.unlock();
}

bool DriverService::SnatTranslate(DriverIOContext* context)
{
	bool result = false;

	if (nat_service_)
	{
		PPACKET_S packageInfo = reinterpret_cast<PPACKET_S>(context->buffer);

		context->bufferOffset = sizeof(PACKET_S);

		if (!nat_service_->ModifyUploadPacket((uint8_t *)(packageInfo->buff), packageInfo->data_len, packageInfo))
		{
			LOGINFO("up load nat package faild buffer length %u, data direction %u", packageInfo->data_len, packageInfo->direction);
			
			result = false;
		}
		else
		{
			result = true;
		}
	}

	return result;
}

bool DriverService::DnatTranslate(DriverIOContext* context)
{
	bool result = false;

	if (nat_service_)
	{
		PACKET_S packageInfo = { 0 };

		context->bufferOffset = sizeof(INJECT_BUFF);

		if (!nat_service_->ModifyDnloadPacket((uint8_t *)(context->buffer + context->bufferOffset), context->buffer_size - context->bufferOffset, &packageInfo))
		{
			LOGINFO("dn load nat package faild");

			result = false;
		}
		else
		{
			PINJECT_BUFF injectBuff = reinterpret_cast<PINJECT_BUFF>(context->buffer);

			injectBuff->Direction = !!!(packageInfo.direction);
			injectBuff->IfIdx = packageInfo.if_idx;
			injectBuff->Loopback = false;
			injectBuff->SubIfIdx = packageInfo.sub_if_idx;
			injectBuff->PseudoIPChecksum = 1;
			injectBuff->PseudoTCPChecksum = 1;
			injectBuff->PseudoUDPChecksum = 1;
			injectBuff->Reserved = 0;
			injectBuff->Timestamp = ::GetCurrentTime();
			injectBuff->Length = context->buffer_size - context->bufferOffset;

			result = true;
		}
	}

	return result;
}

void DriverService::postQuitMessage()
{
	IncreasePendingIOCount();
	DriverIOContext* context = AllocIOContext();

	context->io_type = DriverIOContext::TYPE_QUIT;

	BOOL ret = ::PostQueuedCompletionStatus(iocp_handle_, 0, 0, &context->overlapped);
	if (!ret)
	{
		LOGINFO("post queue message failed error number %u", GetLastError());

		ReleaseIOContext(context);
		DecreasePendingIOCount();
	}


	return;
}

void DriverService::postWriteMessage()
{
	IncreasePendingIOCount();
	DriverIOContext* context = AllocIOContext();

	context->io_type = DriverIOContext::TYPE_WRITE_ACTION;

	BOOL ret = ::PostQueuedCompletionStatus(iocp_handle_, 0, 0, &context->overlapped);
	if (!ret)
	{
		LOGINFO("post queue message failed error number %u", GetLastError());

		ReleaseIOContext(context);
		DecreasePendingIOCount();
	}


	return;
}

// static
DWORD DriverService::DriverThread(void* param) {
  SetNameInternal(GetCurrentThreadId(), "DriverServiceThread");

  DriverService* self = reinterpret_cast<DriverService*>(param);
  while (!self->NeedStopLoop()) {
    DWORD bytes_transferred = 0;
    ULONG_PTR key;
    LPOVERLAPPED overlapped = nullptr;

    BOOL ret = ::GetQueuedCompletionStatus(self->iocp_handle_, &bytes_transferred, &key, &overlapped, INFINITE);

    if (ret) {
      DriverIOContext* context = reinterpret_cast<DriverIOContext*>(overlapped);
      switch (context->io_type) {
      case DriverIOContext::TYPE_READ: {
        if (self->SnatTranslate(context))//单线程模型条件
        {
		  std::lock_guard<std::mutex> lock(self->readLock);
          self->InitFrameBuffer();
          auto data_size = bytes_transferred - context->bufferOffset;
          std::memcpy(self->frame_buffer.data(), context->buffer + context->bufferOffset, data_size);

          self->frame_buffer.set_size(data_size);
          // 往隧道发送
          self->open_vpn_client_->send_data_by_transport(self->frame_buffer);
        }
		//正常读请求成功销毁
		self->DecreasePendingIOCount();

        // 只有不退出才继续投递，如果退出，或者投递失败，应该删除
        if (self->will_exit_ || !self->PostDriverIO(context)) {
          self->ReleaseIOContext(context);
        }

        break;
      }

      case DriverIOContext::TYPE_WRITE:
        // 读请求全部直接回收.
		
        self->ReleaseIOContext(context);
        self->DecreasePendingIOCount();
        break;
	  case DriverIOContext::TYPE_WRITE_ACTION:
	  case DriverIOContext::TYPE_QUIT:
		  {
			self->ReleaseIOContext(context);
			self->DecreasePendingIOCount();
			break;
		  }
	  }
    } else if (overlapped != nullptr) {
      DriverIOContext* context = reinterpret_cast<DriverIOContext*>(overlapped);
      LOGINFO("DriverService::IOCP complete but failed, %s failed, error is %u", context->io_type == DriverIOContext::TYPE_READ ? "read" : "write", ::GetLastError());
      // 这里是失败的请求，直接回收
      self->ReleaseIOContext(context);
      self->DecreasePendingIOCount();
    }
	if (self->cached_buffer_ptrs_.size())
	{
		UINT32 size = self->cached_buffer_ptrs_.size();
		if (!self->will_exit_) {
			// 这里有空隙投递一下读请求.
			self->ProcessAllPendingWriteIO();
		}

	}

  }

  return 0;
}

DriverIOContext* DriverService::AllocIOContext() {
  DriverIOContext* context;
  std::lock_guard<std::mutex> lock(mutexIoCacheContex);

  if (!cached_io_contexts_.empty()) {
    context = cached_io_contexts_.front();
    cached_io_contexts_.pop_front();
  } else {
    context = new DriverIOContext;
  }

  return context;
}

void DriverService::ReleaseIOContext(DriverIOContext* context) {
  std::lock_guard<std::mutex> lock(mutexIoCacheContex);
  cached_io_contexts_.push_back(context);
}

bool DriverService::PostDriverIO(DriverIOContext* context) {
  if (context == nullptr)
    return false;

  ZeroMemory(&context->overlapped, sizeof(context->overlapped));
  DWORD transferred_size = 0;
  BOOL ret = FALSE;
  if (context->io_type == DriverIOContext::TYPE_READ) {
    ret = ::ReadFile(context->file_handle, &context->buffer, context->buffer_size, &transferred_size, &context->overlapped);
  } else {
    ret = ::WriteFile(context->file_handle, &context->buffer, context->buffer_size, &transferred_size, &context->overlapped);
  }

  bool success = false;
  if (!ret) {
    success = ::GetLastError() == ERROR_IO_PENDING;
  } else {
    success = true;
  }

  if (success) {
    IncreasePendingIOCount();
  } else {
    LOGINFO("DriverService::Post IOCP %s opt failed, error is %u", context->io_type == DriverIOContext::TYPE_READ? "read" : "write", ::GetLastError());
  }
}

void DriverService::IncreasePendingIOCount() {
	InterlockedIncrement(&iocp_context_count_);
}

void DriverService::DecreasePendingIOCount() {
  
  UINT32 value = 0;
  InterlockedExchange(&value, iocp_context_count_);

  if (value > 0) {
	  InterlockedDecrement(&iocp_context_count_);
  }
}