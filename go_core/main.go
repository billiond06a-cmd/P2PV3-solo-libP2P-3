// Package main 用于将 Go 核心构建为 Flutter 的动态库。
// 它直接包含所有需要导出的 FFI 函数，避免了包之间的循环依赖问题。
package main

/*
#cgo CFLAGS: -Werror
#include <stdlib.h>

// 定义节点信息的 C 结构体
typedef struct {
    char* id;
    char** addrs;
    int addrs_len;
} PeerAddrInfo;

// 定义节点状态的 C 结构体
typedef struct {
    bool initialized;
    bool started;
    char* status;
    char* connect_code;
    char* external_ip;
    char* local_ip;
    int bound_port;
    bool is_discovery_server;
    PeerAddrInfo* peers;
    int peers_len;
} NodeStatus;

// 定义聊天消息的回调函数类型
typedef void (*MessageHandler)(const char* peerID, const char* message, const char* timestamp);
*/
import "C"

import (
	"encoding/json"
	"log"
	"sync"
	"time"
	"unsafe"

	"vlannet/internal/p2p"

	"github.com/libp2p/go-libp2p/core/peer"
)

// FFIManager 管理 FFI 绑定的状态和资源
type FFIManager struct {
	// 保护并发访问的互斥锁
	mu sync.RWMutex

	// P2P 节点实例
	node *p2p.Node

	// 连接码管理器
	codeMgr *p2p.ConnectCodeManager

	// 聊天消息处理回调指针
	messageHandler C.MessageHandler

	// 节点状态缓存，避免重复计算和序列化
	statusCache struct {
		mu         sync.RWMutex
		jsonData   string    // 缓存的JSON数据
		lastUpdate time.Time // 最后更新时间
		validUntil time.Time // 缓存有效期
	}

	// 节点列表缓存
	peersCache struct {
		mu         sync.RWMutex
		jsonData   string    // 缓存的JSON数据
		lastUpdate time.Time // 最后更新时间
		validUntil time.Time // 缓存有效期
	}

	// 缓存有效期配置
	cacheTTL time.Duration // 缓存有效时间
}

// 全局 FFI 管理器实例
var manager = &FFIManager{
	// 设置缓存有效期为5秒，平衡实时性和性能
	cacheTTL: 5 * time.Second,
}

// main 是一个虚拟函数，用于允许构建为动态库。
func main() {
	// 此函数故意为空。
	// 实际功能在 FFI 绑定中。
}

// InitNode 初始化一个新的 P2P 节点。
//
//export InitNode
func InitNode(mode C.int, bindIP *C.char, port C.int) C.int {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	// 参数验证
	if bindIP == nil {
		log.Printf("错误：bindIP 不能为空")
		return 0
	}

	// 将 C 参数转换为 Go 类型
	goMode := p2p.Mode(mode)
	goBindIP := C.GoString(bindIP)
	goPort := int(port)

	// 创建新节点
	newNode, err := p2p.NewNode(goMode, goBindIP, goPort)
	if err != nil {
		log.Printf("初始化节点失败: %v", err)
		return 0
	}

	// 创建连接码管理器
	codeMgr := p2p.NewConnectCodeManager()

	// 更新管理器状态
	manager.node = newNode
	manager.codeMgr = codeMgr
	manager.messageHandler = nil

	return 1
}

// StartNode 启动 P2P 节点。
//
//export StartNode
func StartNode() C.int {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil {
		log.Printf("错误：节点未初始化")
		return 0
	}

	// 启动节点
	err := manager.node.Start()
	if err != nil {
		log.Printf("启动节点失败: %v", err)
		return 0
	}

	return 1
}

// SetNodeMode 设置 P2P 节点的运行模式。
//
//export SetNodeMode
func SetNodeMode(mode C.int) C.int {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil {
		log.Printf("错误：节点未初始化")
		return 0
	}

	// 将 C 参数转换为 Go 类型
	goMode := p2p.Mode(mode)
	manager.node.Mode = goMode

	// 更新 IsDiscoveryServer 标志
	manager.node.IsDiscoveryServer = (goMode == p2p.ServerMode)

	log.Printf("节点模式已更新为: %s", manager.node.ModeString())
	log.Printf("IsDiscoveryServer: %v", manager.node.IsDiscoveryServer)

	return 1
}

// StopNode 停止 P2P 节点。
//
//export StopNode
func StopNode() C.int {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil {
		log.Printf("错误：节点未初始化")
		return 0
	}

	// 停止节点
	manager.node.Stop()

	// 清理资源
	manager.node = nil
	manager.codeMgr = nil
	manager.messageHandler = nil

	return 1
}

// GenerateConnectCode 生成一个新的连接码。
//
//export GenerateConnectCode
func GenerateConnectCode() *C.char {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil || manager.codeMgr == nil {
		log.Printf("错误：节点或连接码管理器未初始化")
		return C.CString("")
	}

	// 生成连接码
	code, err := manager.codeMgr.GenerateCode(manager.node.Host.ID())
	if err != nil {
		log.Printf("生成连接码失败: %v", err)
		return C.CString("")
	}

	return C.CString(code)
}

// ConnectByCode 使用连接码连接到节点。
//
//export ConnectByCode
func ConnectByCode(code *C.char) C.int {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil || manager.codeMgr == nil {
		log.Printf("错误：节点或连接码管理器未初始化")
		return 0
	}

	if code == nil {
		log.Printf("错误：连接码不能为空")
		return 0
	}

	// 将 C 字符串转换为 Go 字符串
	goCode := C.GoString(code)

	// 通过连接码连接到节点
	err := manager.node.ConnectByCode(goCode, manager.codeMgr)
	if err != nil {
		log.Printf("通过连接码连接失败: %v", err)
		return 0
	}

	return 1
}

// GetPeers 返回已连接节点的列表。
//
//export GetPeers
func GetPeers() *C.char {
	// 首先检查缓存是否有效
	manager.peersCache.mu.RLock()
	cachedData := manager.peersCache.jsonData
	validUntil := manager.peersCache.validUntil
	manager.peersCache.mu.RUnlock()

	// 如果缓存有效且非空，直接返回缓存数据
	if cachedData != "" && time.Now().Before(validUntil) {
		return C.CString(cachedData)
	}

	// 缓存无效，重新获取节点列表
	manager.mu.RLock()
	node := manager.node
	manager.mu.RUnlock()

	var peers []peer.AddrInfo
	if node != nil {
		peers = node.GetPeers()
	} else {
		log.Printf("错误：节点未初始化")
		peers = []peer.AddrInfo{}
	}

	// 转换为 JSON
	jsonData, err := json.Marshal(peers)
	if err != nil {
		log.Printf("序列化节点失败: %v", err)
		return C.CString("[]")
	}

	// 更新缓存
	jsonStr := string(jsonData)
	manager.peersCache.mu.Lock()
	manager.peersCache.jsonData = jsonStr
	manager.peersCache.lastUpdate = time.Now()
	manager.peersCache.validUntil = time.Now().Add(manager.cacheTTL)
	manager.peersCache.mu.Unlock()

	return C.CString(jsonStr)
}

// GetNodeStatus 返回当前节点状态。
//
//export GetNodeStatus
func GetNodeStatus() *C.NodeStatus {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	// 分配 C 内存来存储状态
	statusPtr := (*C.NodeStatus)(C.malloc(C.sizeof_NodeStatus))
	if statusPtr == nil {
		log.Printf("错误：无法分配内存")
		return nil
	}

	// 初始化默认值
	statusPtr.initialized = C.bool(false)
	statusPtr.started = C.bool(false)
	statusPtr.status = C.CString("未初始化")
	statusPtr.connect_code = C.CString("")
	statusPtr.external_ip = C.CString("")
	statusPtr.local_ip = C.CString("")
	statusPtr.bound_port = 0
	statusPtr.is_discovery_server = C.bool(false)
	statusPtr.peers = nil
	statusPtr.peers_len = 0

	if manager.node == nil {
		return statusPtr
	}

	// 获取节点
	peers := manager.node.GetPeers()

	// 创建 C 节点数组
	var cPeers []C.PeerAddrInfo
	var cPeersPtr *C.PeerAddrInfo
	if len(peers) > 0 {
		cPeers = make([]C.PeerAddrInfo, len(peers))
		for i, peer := range peers {
			// 将节点 ID 转换为 C 字符串
			id := C.CString(string(peer.ID))

			// 将地址转换为 C 字符串数组
			cAddrs := make([]*C.char, len(peer.Addrs))
			for j, addr := range peer.Addrs {
				cAddrs[j] = C.CString(addr.String())
			}

			// 创建节点信息结构体
			cPeers[i] = C.PeerAddrInfo{
				id:        id,
				addrs:     &cAddrs[0],
				addrs_len: C.int(len(cAddrs)),
			}
		}
		cPeersPtr = &cPeers[0]
	}

	// 获取连接码
	connectCode := ""
	if manager.codeMgr != nil {
		connectCode, _ = manager.codeMgr.GetCode(manager.node.Host.ID())
		// 如果没有连接码，生成一个
		if connectCode == "" {
			connectCode, _ = manager.codeMgr.GenerateCode(manager.node.Host.ID())
		}
	}

	// 获取节点状态
	statusStr := "运行中"
	if !manager.node.IsStarted() {
		statusStr = "已初始化但未启动"
	}

	// 更新状态结构体
	statusPtr.initialized = C.bool(true)
	statusPtr.started = C.bool(manager.node.IsStarted())
	statusPtr.status = C.CString(statusStr)
	statusPtr.connect_code = C.CString(connectCode)
	statusPtr.external_ip = C.CString(manager.node.ExternalIP)
	statusPtr.local_ip = C.CString(manager.node.LocalIP)
	statusPtr.bound_port = C.int(manager.node.BoundPort)
	statusPtr.is_discovery_server = C.bool(manager.node.IsDiscoveryServer)
	statusPtr.peers = cPeersPtr
	statusPtr.peers_len = C.int(len(cPeers))

	return statusPtr
}

// FreeNodeStatus 释放为 NodeStatus 分配的内存。
//
//export FreeNodeStatus
func FreeNodeStatus(status *C.NodeStatus) {
	if status == nil {
		return
	}

	// 释放状态字符串
	if status.status != nil {
		C.free(unsafe.Pointer(status.status))
		status.status = nil
	}

	// 释放连接码字符串
	if status.connect_code != nil {
		C.free(unsafe.Pointer(status.connect_code))
		status.connect_code = nil
	}

	// 释放外网IP字符串
	if status.external_ip != nil {
		C.free(unsafe.Pointer(status.external_ip))
		status.external_ip = nil
	}

	// 释放局域网IP字符串
	if status.local_ip != nil {
		C.free(unsafe.Pointer(status.local_ip))
		status.local_ip = nil
	}

	// 释放节点
	if status.peers != nil {
		for i := 0; i < int(status.peers_len); i++ {
			peer := (*C.PeerAddrInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(status.peers)) + uintptr(i)*unsafe.Sizeof(C.PeerAddrInfo{})))

			// 释放节点 ID
			if peer.id != nil {
				C.free(unsafe.Pointer(peer.id))
				peer.id = nil
			}

			// 释放地址
			if peer.addrs != nil {
				for j := 0; j < int(peer.addrs_len); j++ {
					addr := (*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(peer.addrs)) + uintptr(j)*unsafe.Sizeof(*peer.addrs)))
					if addr != nil {
						C.free(unsafe.Pointer(addr))
						addr = nil
					}
				}
			}
		}
	}

	// 释放状态结构体本身
	C.free(unsafe.Pointer(status))
}

// GetNodeStatusJSON 返回当前节点状态的 JSON 字符串。
//
//export GetNodeStatusJSON
func GetNodeStatusJSON() *C.char {
	// 首先检查缓存是否有效
	manager.statusCache.mu.RLock()
	cachedData := manager.statusCache.jsonData
	validUntil := manager.statusCache.validUntil
	manager.statusCache.mu.RUnlock()

	// 如果缓存有效且非空，直接返回缓存数据
	if cachedData != "" && time.Now().Before(validUntil) {
		return C.CString(cachedData)
	}

	// 缓存无效，重新生成状态数据
	manager.mu.RLock()
	node := manager.node
	codeMgr := manager.codeMgr
	manager.mu.RUnlock()

	// 构建状态数据
	statusData := map[string]interface{}{
		"initialized":         false,
		"started":             false,
		"status":              "未初始化",
		"connect_code":        "",
		"external_ip":         "",
		"local_ip":            "",
		"bound_port":          0,
		"is_discovery_server": false,
		"peers":               []interface{}{},
	}

	if node != nil {
		statusData["initialized"] = true
		statusData["started"] = node.IsStarted()

		// 获取状态字符串
		statusStr := "运行中"
		if !node.IsStarted() {
			statusStr = "已初始化但未启动"
		}
		statusData["status"] = statusStr

		// 获取连接码
		connectCode := ""
		if codeMgr != nil {
			connectCode, _ = codeMgr.GetCode(node.Host.ID())
			// 如果没有连接码，生成一个
			if connectCode == "" {
				connectCode, _ = codeMgr.GenerateCode(node.Host.ID())
			}
		}
		statusData["connect_code"] = connectCode

		// 获取 IP 地址
		statusData["external_ip"] = node.ExternalIP
		statusData["local_ip"] = node.LocalIP
		statusData["bound_port"] = node.BoundPort
		statusData["is_discovery_server"] = node.IsDiscoveryServer

		// 获取节点
		peers := node.GetPeers()
		peerList := make([]map[string]interface{}, len(peers))

		for i, peer := range peers {
			// 收集节点地址
			addrStrings := make([]string, len(peer.Addrs))
			for j, addr := range peer.Addrs {
				addrStrings[j] = addr.String()
			}

			peerList[i] = map[string]interface{}{
				"id":    peer.ID.String(),
				"addrs": addrStrings,
			}
		}
		statusData["peers"] = peerList
	}

	// 将状态转换为 JSON
	jsonData, err := json.Marshal(statusData)
	if err != nil {
		log.Printf("序列化节点状态失败: %v", err)
		return C.CString(`{"error":"序列化失败"}`)
	}

	// 更新缓存
	jsonStr := string(jsonData)
	manager.statusCache.mu.Lock()
	manager.statusCache.jsonData = jsonStr
	manager.statusCache.lastUpdate = time.Now()
	manager.statusCache.validUntil = time.Now().Add(manager.cacheTTL)
	manager.statusCache.mu.Unlock()

	return C.CString(jsonStr)
}

// SendMessage 向节点发送聊天消息。
//
//export SendMessage
func SendMessage(peerID *C.char, message *C.char) C.int {
	// 首先进行参数检查，不需要加锁
	if peerID == nil || message == nil {
		log.Printf("错误：peerID 或 message 不能为空")
		return 0
	}

	// 转换C字符串，不需要加锁
	goPeerID := C.GoString(peerID)
	goMessage := C.GoString(message)

	// 只在获取节点时加读锁，因为SendMessage方法内部会处理并发
	manager.mu.RLock()
	node := manager.node
	manager.mu.RUnlock()

	if node == nil {
		log.Printf("错误：节点未初始化")
		return 0
	}

	// 发送消息，节点的SendMessage方法内部会处理并发
	err := node.SendMessage(goPeerID, goMessage)
	if err != nil {
		log.Printf("发送消息失败: %v", err)
		return 0
	}

	return 1
}

// RegisterMessageHandler 注册传入聊天消息的回调。
//
//export RegisterMessageHandler
func RegisterMessageHandler(handler unsafe.Pointer) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	// 保存 C 回调函数指针
	manager.messageHandler = C.MessageHandler(handler)

	// 在协议管理器中设置 OnChatMessage 回调
	if manager.node != nil && manager.node.ProtocolManager != nil {
		manager.node.ProtocolManager.OnChatMessage = func(peerID string, message string, timestamp string) {
			// 调用 C 回调函数的包装函数
			callMessageHandler(peerID, message, timestamp)
		}
	}
}

// callMessageHandler 安全地调用 C 消息处理回调
func callMessageHandler(peerID, message, timestamp string) {
	manager.mu.Lock()
	handler := manager.messageHandler
	manager.mu.Unlock()

	// 如果注册了回调，调用它
	if handler != nil {
		// 将 Go 字符串转换为 C 字符串
		cPeerID := C.CString(peerID)
		cMessage := C.CString(message)
		cTimestamp := C.CString(timestamp)

		// 使用 Go 的 cgo 机制直接调用 C 函数指针
		// 注意：这是 Go 调用 C 函数指针的正确方式
		// 我们需要使用 unsafe.Pointer 来转换函数指针
		// 然后通过汇编指令调用它
		// 但在 Go 1.16+ 中，我们可以直接调用 C 函数指针
		// 通过将其转换为函数类型
		callback := func(peerID, msg, ts *C.char) {
			// 这个函数会被 Go 编译器特殊处理
			// 用于调用 C 函数指针
		}

		// 获取回调函数的地址
		callbackAddr := *(*uintptr)(unsafe.Pointer(&callback))

		// 将 C 函数指针转换为相同类型的函数
		cHandler := *(*func(*C.char, *C.char, *C.char))(unsafe.Pointer(&callbackAddr))

		// 更新回调函数的地址为我们的 C 函数指针
		*(*uintptr)(unsafe.Pointer(&cHandler)) = uintptr(unsafe.Pointer(handler))

		// 调用 C 回调函数
		cHandler(cPeerID, cMessage, cTimestamp)

		// 释放 C 字符串以避免内存泄漏
		C.free(unsafe.Pointer(cPeerID))
		C.free(unsafe.Pointer(cMessage))
		C.free(unsafe.Pointer(cTimestamp))
	} else {
		// 如果没有注册回调，只是打印消息
		log.Printf("收到来自 %s 的聊天消息: %s", peerID, message)
	}
}

// FreeString 释放由 Go 分配的 C 字符串。
//
//export FreeString
func FreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// GetChatMessages 获取所有未处理的聊天消息。
// 返回格式为 JSON 字符串数组，每个元素包含：
// - peerID: 发送消息的节点 ID
// - message: 消息内容
// - timestamp: 消息时间戳
//
//export GetChatMessages
func GetChatMessages() *C.char {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil {
		log.Printf("错误：节点未初始化")
		return C.CString("[]")
	}

	// 调用节点的 GetChatMessagesJSON 方法获取消息
	messagesJSON, err := manager.node.GetChatMessagesJSON()
	if err != nil {
		log.Printf("获取聊天消息失败: %v", err)
		return C.CString("[]")
	}

	return C.CString(messagesJSON)
}

// ConnectByIP 使用 IP 地址或域名连接到其他节点。
//
//export ConnectByIP
func ConnectByIP(ipOrDomain *C.char, port C.int) C.int {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.node == nil {
		log.Printf("错误：节点未初始化")
		return 0
	}

	if ipOrDomain == nil {
		log.Printf("错误：IP 或域名不能为空")
		return 0
	}

	// 将 C 字符串转换为 Go 字符串
	goIpOrDomain := C.GoString(ipOrDomain)
	goPort := int(port)

	// 通过 IP/域名连接到节点
	err := manager.node.ConnectByIP(goIpOrDomain, goPort)
	if err != nil {
		log.Printf("通过 IP/域名连接失败: %v", err)
		return 0
	}

	return 1
}